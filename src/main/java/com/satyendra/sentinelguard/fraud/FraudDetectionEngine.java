/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.FraudAlert;
import com.satyendra.sentinelguard.domain.FraudSignal;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.domain.ThreatLevel;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Scores a request against the behavioural heuristics and, when the aggregated
 * risk reaches the configured band, hands an alert to the Kafka side channel.
 *
 * <h3>Scoring model</h3>
 * Each {@link FraudSignal} contributes an additive weight; the sum is mapped to
 * a {@link ThreatLevel}. Weights are tuned so that no single weak indicator can
 * reach the default {@link ThreatLevel#MEDIUM} publication floor on its own,
 * while any two correlated indicators can. That keeps the topic signal-dense
 * instead of drowning analysts in "anonymous caller with no User-Agent" noise.
 *
 * <h3>Stateful versus stateless heuristics</h3>
 * Stateless checks (headers, identity provenance) are pure functions of the
 * fingerprint. Stateful checks (rejection velocity, path enumeration) are
 * measured against atomic Redis sliding windows, which is what makes them
 * accurate across a horizontally scaled fleet rather than per-pod.
 *
 * <h3>Failure policy</h3>
 * Detection is advisory. If Redis is unreachable the engine completes empty:
 * a request is never failed because the fraud subsystem is unhealthy.
 *
 * @author Satyendra Singh
 */
@Component
public class FraudDetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(FraudDetectionEngine.class);

    private static final String EVALUATION_METRIC = "sentinelguard.fraud.evaluations";

    private final SlidingWindowCounter windowCounter;
    private final FraudAlertPublisher alertPublisher;
    private final SentinelGuardProperties properties;
    private final MeterRegistry meterRegistry;
    private final List<Pattern> suspiciousUserAgents;

    /**
     * @param windowCounter  distributed sliding-window counter
     * @param alertPublisher alert transport
     * @param properties     engine configuration
     * @param meterRegistry  Micrometer registry
     * @throws IllegalStateException when a configured User-Agent pattern is not
     *                               a valid regular expression
     */
    public FraudDetectionEngine(SlidingWindowCounter windowCounter,
                                FraudAlertPublisher alertPublisher,
                                SentinelGuardProperties properties,
                                MeterRegistry meterRegistry) {
        this.windowCounter = windowCounter;
        this.alertPublisher = alertPublisher;
        this.properties = properties;
        this.meterRegistry = meterRegistry;
        this.suspiciousUserAgents = compile(properties.getFraud().getSuspiciousUserAgentPatterns());
    }

    /**
     * Evaluates one request and publishes an alert when warranted.
     *
     * @param fingerprint request metadata
     * @param verdict     admission decision already taken for this request
     * @return the published alert, or an empty {@link Mono} when the request is
     *         clean, suppressed below the publication floor, or when the
     *         detection backend was unavailable
     */
    public Mono<FraudAlert> inspect(RequestFingerprint fingerprint, RateLimitVerdict verdict) {
        SentinelGuardProperties.Fraud config = properties.getFraud();
        if (!config.isEnabled()) {
            return Mono.empty();
        }

        Duration window = config.getObservationWindow();
        Duration ttl = config.getWindowTtl();

        // Only rejections are written to the velocity window: successful calls
        // must not inflate a counter whose whole purpose is to measure abuse.
        Mono<Long> rejectionVelocity = verdict.allowed()
                ? Mono.just(0L)
                : windowCounter.observe(key(config, "rej", fingerprint), uniqueMember(), window, ttl);

        Mono<Long> distinctPaths =
                windowCounter.observe(key(config, "path", fingerprint), fingerprint.path(), window, ttl);

        return Mono.zip(rejectionVelocity, distinctPaths)
                .flatMap(observations -> score(fingerprint, verdict, observations))
                .onErrorResume(error -> {
                    count("error", ThreatLevel.NONE);
                    log.warn("Fraud evaluation failed [correlationId={}, identity={}]; "
                                    + "request already served, continuing without an alert.",
                            fingerprint.correlationId(), fingerprint.identity().asKeySegment(), error);
                    return Mono.empty();
                });
    }

    /**
     * Applies every heuristic and decides whether the result is publishable.
     *
     * @param fingerprint  request metadata
     * @param verdict      admission decision
     * @param observations rejection velocity (T1) and distinct path count (T2)
     * @return the published alert, or empty when below the publication floor
     */
    private Mono<FraudAlert> score(RequestFingerprint fingerprint, RateLimitVerdict verdict,
                                   Tuple2<Long, Long> observations) {

        SentinelGuardProperties.Fraud config = properties.getFraud();
        long rejectionVelocity = observations.getT1();
        long distinctPaths = observations.getT2();

        List<FraudSignal> signals = new ArrayList<>();

        if (!verdict.allowed()) {
            signals.add(FraudSignal.RATE_LIMIT_BREACH);
        }
        if (rejectionVelocity >= config.getBurstRejectionThreshold()) {
            signals.add(FraudSignal.BURST_VELOCITY);
        }
        if (distinctPaths > config.getDistinctPathThreshold()) {
            signals.add(FraudSignal.PATH_ENUMERATION);
        }
        if (!fingerprint.hasUserAgent()) {
            signals.add(FraudSignal.MISSING_USER_AGENT);
        } else if (isSuspiciousUserAgent(fingerprint.userAgent())) {
            signals.add(FraudSignal.SUSPICIOUS_USER_AGENT);
        }
        if (fingerprint.identity().isAnonymous()) {
            signals.add(FraudSignal.ANONYMOUS_IDENTITY);
        }

        if (signals.isEmpty()) {
            count("clean", ThreatLevel.NONE);
            return Mono.empty();
        }

        int riskScore = signals.stream().mapToInt(FraudSignal::weight).sum();
        ThreatLevel threatLevel = ThreatLevel.fromScore(riskScore);

        if (!threatLevel.atLeast(config.getPublishThreshold())) {
            count("suppressed", threatLevel);
            return Mono.empty();
        }

        FraudAlert alert = FraudAlert.of(fingerprint, verdict.policyName(), signals, riskScore);
        count("alerted", threatLevel);

        return alertPublisher.publish(alert).thenReturn(alert);
    }

    /**
     * @param userAgent reported User-Agent, never blank here
     * @return {@code true} when any configured automation signature matches
     */
    private boolean isSuspiciousUserAgent(String userAgent) {
        for (Pattern pattern : suspiciousUserAgents) {
            if (pattern.matcher(userAgent).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds a window key scoped to one identity and one dimension.
     *
     * @param config      fraud configuration
     * @param dimension   short dimension discriminator
     * @param fingerprint request metadata
     * @return Redis key
     */
    private String key(SentinelGuardProperties.Fraud config, String dimension,
                       RequestFingerprint fingerprint) {
        return config.getKeyPrefix() + ':' + dimension + ':'
                + fingerprint.identity().asKeySegment();
    }

    /**
     * @return a member guaranteed unique per call, turning the distinct-count
     *         window into an event-volume window
     */
    private String uniqueMember() {
        return Long.toUnsignedString(ThreadLocalRandom.current().nextLong(), 36);
    }

    private void count(String outcome, ThreatLevel threatLevel) {
        Counter.builder(EVALUATION_METRIC)
                .description("Fraud evaluations by outcome")
                .tag("outcome", outcome)
                .tag("threat", threatLevel.name())
                .register(meterRegistry)
                .increment();
    }

    private static List<Pattern> compile(List<String> expressions) {
        List<Pattern> compiled = new ArrayList<>(expressions.size());
        for (String expression : expressions) {
            try {
                compiled.add(Pattern.compile(expression));
            } catch (PatternSyntaxException cause) {
                throw new IllegalStateException("Invalid regular expression in "
                        + "sentinelguard.fraud.suspicious-user-agent-patterns: " + expression, cause);
            }
        }
        return List.copyOf(compiled);
    }
}
