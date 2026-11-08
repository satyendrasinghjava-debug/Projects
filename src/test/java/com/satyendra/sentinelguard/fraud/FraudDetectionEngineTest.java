/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.FraudAlert;
import com.satyendra.sentinelguard.domain.FraudSignal;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.domain.ThreatLevel;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link FraudDetectionEngine}: every heuristic, every scoring
 * boundary and every failure mode.
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("FraudDetectionEngine")
class FraudDetectionEngineTest {

    private static final Instant NOW = Instant.parse("2026-04-15T12:00:00Z");

    private static final RateLimitPolicy POLICY = new RateLimitPolicy(
            "payments-strict", 20L, 20L, Duration.ofMinutes(1), 1L, Duration.ofMinutes(10));

    @Mock
    private SlidingWindowCounter windowCounter;

    @Mock
    private FraudAlertPublisher alertPublisher;

    private SentinelGuardProperties properties;
    private MeterRegistry meterRegistry;
    private FraudDetectionEngine engine;

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        properties.getFraud().setBurstRejectionThreshold(5);
        properties.getFraud().setDistinctPathThreshold(15);
        properties.getFraud().setPublishThreshold(ThreatLevel.MEDIUM);

        meterRegistry = new SimpleMeterRegistry();
        engine = newEngine();

        stubVelocity(0L);
        stubDistinctPaths(1L);
        doReturn(Mono.empty()).when(alertPublisher).publish(any(FraudAlert.class));
    }

    // =====================================================================
    // Clean traffic
    // =====================================================================

    @Test
    @DisplayName("a clean, credentialled, admitted request raises nothing")
    void cleanRequestRaisesNothing() {
        StepVerifier.create(engine.inspect(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                        allowed()))
                .verifyComplete();

        verify(alertPublisher, never()).publish(any());
        assertThat(evaluationCount("clean", ThreatLevel.NONE)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("an admitted request never writes to the rejection-velocity window")
    void admittedRequestDoesNotInflateVelocityWindow() {
        engine.inspect(fingerprint("Mozilla/5.0", IdentityType.API_KEY), allowed())
                .block(Duration.ofSeconds(1));

        verify(windowCounter, never()).observe(contains(":rej:"), anyString(), any(), any());
        verify(windowCounter).observe(contains(":path:"), anyString(), any(), any());
    }

    @Test
    @DisplayName("weak signals alone stay below the publication floor")
    void weakSignalsAreSuppressed() {
        // Missing User-Agent (15) + anonymous identity (10) = 25 -> LOW.
        StepVerifier.create(engine.inspect(fingerprint(null, IdentityType.ANONYMOUS), allowed()))
                .verifyComplete();

        verify(alertPublisher, never()).publish(any());
        assertThat(evaluationCount("suppressed", ThreatLevel.LOW)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("disabling the engine short-circuits every backend call")
    void disabledEngineDoesNothing() {
        properties.getFraud().setEnabled(false);

        StepVerifier.create(engine.inspect(fingerprint(null, IdentityType.ANONYMOUS), denied()))
                .verifyComplete();

        verifyNoInteractions(windowCounter);
        verifyNoInteractions(alertPublisher);
    }

    // =====================================================================
    // Heuristics
    // =====================================================================

    @Test
    @DisplayName("a rejection combined with an anonymous identity is published as MEDIUM")
    void rejectionPlusAnonymityIsPublished() {
        FraudAlert alert = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.REMOTE_IP),
                denied(), engine);

        // Breach (25) + anonymous is not set for REMOTE_IP, so score stays 25 -> LOW.
        assertThat(alert).isNull();

        FraudAlert anonymousAlert = inspectAndCapture(
                fingerprint("Mozilla/5.0", IdentityType.ANONYMOUS), denied(), newEngine());

        // Breach (25) + anonymous identity (10) = 35 -> MEDIUM.
        assertThat(anonymousAlert).isNotNull();
        assertThat(anonymousAlert.riskScore()).isEqualTo(35);
        assertThat(anonymousAlert.threatLevel()).isEqualTo(ThreatLevel.MEDIUM);
        assertThat(anonymousAlert.signals()).containsExactly(
                FraudSignal.RATE_LIMIT_BREACH, FraudSignal.ANONYMOUS_IDENTITY);
    }

    @Test
    @DisplayName("sustained rejections escalate to BURST_VELOCITY and HIGH")
    void burstVelocityEscalates() {
        stubVelocity(5L);

        FraudAlert alert = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                denied(), engine);

        // Breach (25) + burst (30) = 55 -> HIGH.
        assertThat(alert).isNotNull();
        assertThat(alert.riskScore()).isEqualTo(55);
        assertThat(alert.threatLevel()).isEqualTo(ThreatLevel.HIGH);
        assertThat(alert.signals()).contains(FraudSignal.BURST_VELOCITY);
        assertThat(alert.policyName()).isEqualTo("payments-strict");
        assertThat(alert.correlationId()).isEqualTo("corr-9");
        assertThat(alert.alertId()).isNotBlank();
    }

    @Test
    @DisplayName("the burst threshold is inclusive at its boundary and silent below it")
    void burstThresholdBoundary() {
        stubVelocity(4L);
        FraudAlert below = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                denied(), engine);
        assertThat(below).isNull(); // 25 -> LOW, suppressed

        stubVelocity(5L);
        FraudAlert atBoundary = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                denied(), newEngine());
        assertThat(atBoundary).isNotNull();
        assertThat(atBoundary.signals()).contains(FraudSignal.BURST_VELOCITY);
    }

    @Test
    @DisplayName("distinct-path cardinality above the threshold raises PATH_ENUMERATION")
    void pathEnumerationDetected() {
        stubDistinctPaths(16L);

        FraudAlert alert = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                allowed(), engine);

        // Enumeration (25) alone is LOW, so pair it with a rejection for a real alert.
        assertThat(alert).isNull();

        stubDistinctPaths(16L);
        FraudAlert escalated = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                denied(), newEngine());

        assertThat(escalated).isNotNull();
        assertThat(escalated.signals())
                .containsExactly(FraudSignal.RATE_LIMIT_BREACH, FraudSignal.PATH_ENUMERATION);
        assertThat(escalated.riskScore()).isEqualTo(50);
        assertThat(escalated.threatLevel()).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    @DisplayName("the path threshold is exclusive at its boundary")
    void pathThresholdBoundary() {
        stubDistinctPaths(15L);

        FraudAlert alert = inspectAndCapture(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                denied(), engine);

        assertThat(alert).isNull(); // breach only -> LOW
    }

    @Test
    @DisplayName("a scripted User-Agent is flagged, a browser one is not")
    void suspiciousUserAgentDetected() {
        FraudAlert scripted = inspectAndCapture(
                fingerprint("python-requests/2.32.3", IdentityType.API_KEY), denied(), engine);

        // Breach (25) + suspicious agent (20) = 45 -> MEDIUM.
        assertThat(scripted).isNotNull();
        assertThat(scripted.signals())
                .containsExactly(FraudSignal.RATE_LIMIT_BREACH, FraudSignal.SUSPICIOUS_USER_AGENT);
        assertThat(scripted.riskScore()).isEqualTo(45);
    }

    @Test
    @DisplayName("every configured automation signature matches")
    void allConfiguredSignaturesMatch() {
        List<String> agents = List.of("curl/8.7.1", "Wget/1.21", "Scrapy/2.11",
                "sqlmap/1.8", "Go-http-client/2.0", "HeadlessChrome/126.0.0.0",
                "Java/21.0.3", "okhttp/4.12.0");

        for (String agent : agents) {
            FraudAlert alert = inspectAndCapture(fingerprint(agent, IdentityType.API_KEY),
                    denied(), newEngine());
            assertThat(alert)
                    .withFailMessage("expected '%s' to be flagged as automation", agent)
                    .isNotNull();
            assertThat(alert.signals()).contains(FraudSignal.SUSPICIOUS_USER_AGENT);
        }
    }

    @Test
    @DisplayName("a missing User-Agent suppresses the suspicious-agent check")
    void missingUserAgentWins() {
        FraudAlert alert = inspectAndCapture(fingerprint("   ", IdentityType.API_KEY),
                denied(), engine);

        // Breach (25) + missing agent (15) = 40 -> MEDIUM; blank counts as missing.
        assertThat(alert).isNotNull();
        assertThat(alert.signals())
                .containsExactly(FraudSignal.RATE_LIMIT_BREACH, FraudSignal.MISSING_USER_AGENT);
        assertThat(alert.signals()).doesNotContain(FraudSignal.SUSPICIOUS_USER_AGENT);
    }

    @Test
    @DisplayName("a maximally hostile request reaches CRITICAL")
    void criticalEscalation() {
        stubVelocity(50L);
        stubDistinctPaths(400L);

        FraudAlert alert = inspectAndCapture(fingerprint("sqlmap/1.8", IdentityType.ANONYMOUS),
                denied(), engine);

        // 25 + 30 + 25 + 20 + 10 = 110 -> CRITICAL.
        assertThat(alert).isNotNull();
        assertThat(alert.riskScore()).isEqualTo(110);
        assertThat(alert.threatLevel()).isEqualTo(ThreatLevel.CRITICAL);
        assertThat(alert.signals()).hasSize(5);
        assertThat(alert.identityType()).isEqualTo(IdentityType.ANONYMOUS);
        assertThat(alert.clientIp()).isEqualTo("198.51.100.4");
    }

    @Test
    @DisplayName("raising the publication floor silences lower bands")
    void publicationFloorIsHonoured() {
        properties.getFraud().setPublishThreshold(ThreatLevel.CRITICAL);
        stubVelocity(5L);

        StepVerifier.create(engine.inspect(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                        denied()))
                .verifyComplete();

        verify(alertPublisher, never()).publish(any());
        assertThat(evaluationCount("suppressed", ThreatLevel.HIGH)).isEqualTo(1.0d);
    }

    // =====================================================================
    // Resilience
    // =====================================================================

    @Test
    @DisplayName("a detection-backend failure never fails the request")
    void backendFailureIsAbsorbed() {
        doReturn(Mono.error(new IllegalStateException("redis down")))
                .when(windowCounter).observe(anyString(), anyString(), any(), any());

        StepVerifier.create(engine.inspect(fingerprint("curl/8.7.1", IdentityType.ANONYMOUS),
                        denied()))
                .verifyComplete();

        assertThat(evaluationCount("error", ThreatLevel.NONE)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("a transport failure never fails the request")
    void publisherFailureIsAbsorbed() {
        doReturn(Mono.error(new IllegalStateException("kafka down")))
                .when(alertPublisher).publish(any(FraudAlert.class));
        stubVelocity(5L);

        StepVerifier.create(engine.inspect(fingerprint("Mozilla/5.0", IdentityType.API_KEY),
                        denied()))
                .verifyComplete();
    }

    @Test
    @DisplayName("an invalid User-Agent pattern fails the context at startup")
    void invalidPatternFailsFast() {
        properties.getFraud().setSuspiciousUserAgentPatterns(List.of("([unclosed"));

        assertThatThrownBy(this::newEngine)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Invalid regular expression");
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private FraudDetectionEngine newEngine() {
        return new FraudDetectionEngine(windowCounter, alertPublisher, properties, meterRegistry);
    }

    private FraudAlert inspectAndCapture(RequestFingerprint fingerprint, RateLimitVerdict verdict,
                                         FraudDetectionEngine target) {
        return target.inspect(fingerprint, verdict).block(Duration.ofSeconds(2));
    }

    private void stubVelocity(long value) {
        doReturn(Mono.just(value))
                .when(windowCounter).observe(contains(":rej:"), anyString(), any(), any());
    }

    private void stubDistinctPaths(long value) {
        doReturn(Mono.just(value))
                .when(windowCounter).observe(contains(":path:"), anyString(), any(), any());
    }

    private double evaluationCount(String outcome, ThreatLevel threatLevel) {
        return meterRegistry.get("sentinelguard.fraud.evaluations")
                .tag("outcome", outcome)
                .tag("threat", threatLevel.name())
                .counter()
                .count();
    }

    private static RateLimitVerdict allowed() {
        return RateLimitVerdict.allow(POLICY, "bucket", 19L, NOW);
    }

    private static RateLimitVerdict denied() {
        return RateLimitVerdict.deny(POLICY, "bucket", 0L, Duration.ofSeconds(12), NOW);
    }

    private static RequestFingerprint fingerprint(String userAgent, IdentityType type) {
        return new RequestFingerprint("corr-9", new ClientIdentity("identity-value", type),
                "198.51.100.4", "POST", "/api/v1/transactions", userAgent, NOW);
    }

    /** Documents the published alert contract; a consumer depends on these fields. */
    @Test
    @DisplayName("published alerts carry an immutable signal list")
    void alertSignalsAreImmutable() {
        stubVelocity(5L);
        ArgumentCaptor<FraudAlert> captor = ArgumentCaptor.forClass(FraudAlert.class);

        engine.inspect(fingerprint("Mozilla/5.0", IdentityType.API_KEY), denied())
                .block(Duration.ofSeconds(1));

        verify(alertPublisher).publish(captor.capture());
        assertThatThrownBy(() -> captor.getValue().signals().add(FraudSignal.ANONYMOUS_IDENTITY))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
