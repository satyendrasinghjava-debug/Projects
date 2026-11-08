/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.fraud.FraudDetectionEngine;
import com.satyendra.sentinelguard.limiter.RateLimitPolicyResolver;
import com.satyendra.sentinelguard.limiter.RateLimiter;
import com.satyendra.sentinelguard.web.dto.RateLimitErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * The engine's entry point: a fully reactive {@link WebFilter} that admits or
 * sheds every inbound exchange before it reaches any handler.
 *
 * <h3>Why a WebFilter and not a controller or an annotation</h3>
 * Admission control must happen before routing, before body decoding and before
 * any business bean is touched: work performed on a request that is about to be
 * rejected is exactly the work an attacker is trying to make you do. A filter is
 * also transport-wide, so a newly added endpoint is protected by default rather
 * than by remembering to annotate it.
 *
 * <h3>Decision flow</h3>
 * <ol>
 *   <li>Bypass excluded paths (health probes, metrics scrape) so that an
 *       aggressive caller can never starve the platform's own observability.</li>
 *   <li>Fingerprint the exchange, resolve the policy, consume a token.</li>
 *   <li>Hand the outcome to the fraud engine on a detached subscription, so
 *       scoring and Kafka I/O add nothing to the customer's latency.</li>
 *   <li>Continue the chain with advisory headers, or reject with
 *       <em>429 Too Many Requests</em> and a precise {@code Retry-After}.</li>
 * </ol>
 *
 * @author Satyendra Singh
 */
@Component
@Order(RateLimitWebFilter.ORDER)
public class RateLimitWebFilter implements WebFilter {

    /** Runs immediately after correlation id establishment. */
    public static final int ORDER = -150;

    /** Advisory header: bucket capacity. */
    public static final String HEADER_LIMIT = "X-RateLimit-Limit";

    /** Advisory header: tokens left after this request. */
    public static final String HEADER_REMAINING = "X-RateLimit-Remaining";

    /** Advisory header: epoch-second at which the bucket replenishes. */
    public static final String HEADER_RESET = "X-RateLimit-Reset";

    /** Advisory header: the policy that produced the decision. */
    public static final String HEADER_POLICY = "X-RateLimit-Policy";

    /** Advisory header: set when the decision came from a degraded backend. */
    public static final String HEADER_DEGRADED = "X-RateLimit-Degraded";

    private static final Logger log = LoggerFactory.getLogger(RateLimitWebFilter.class);

    /**
     * Last-resort body used only if the engine's own error DTO cannot be
     * serialised; a caller must never receive an empty 429.
     */
    private static final byte[] FALLBACK_BODY =
            ("{\"status\":429,\"title\":\"Too Many Requests\","
                    + "\"detail\":\"Rate limit exceeded.\"}").getBytes(StandardCharsets.UTF_8);

    private final RateLimiter rateLimiter;
    private final RateLimitPolicyResolver policyResolver;
    private final RequestFingerprintFactory fingerprintFactory;
    private final FraudDetectionEngine fraudDetectionEngine;
    private final SentinelGuardProperties properties;
    private final ObjectMapper objectMapper;

    /**
     * @param rateLimiter          distributed token bucket
     * @param policyResolver       policy lookup
     * @param fingerprintFactory   exchange to fingerprint mapper
     * @param fraudDetectionEngine behavioural scoring engine
     * @param properties           engine configuration
     * @param objectMapper         application mapper used for the 429 body
     */
    public RateLimitWebFilter(RateLimiter rateLimiter,
                              RateLimitPolicyResolver policyResolver,
                              RequestFingerprintFactory fingerprintFactory,
                              FraudDetectionEngine fraudDetectionEngine,
                              SentinelGuardProperties properties,
                              ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.policyResolver = policyResolver;
        this.fingerprintFactory = fingerprintFactory;
        this.fraudDetectionEngine = fraudDetectionEngine;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (!properties.getRateLimit().isEnabled() || policyResolver.isExcluded(path)) {
            return chain.filter(exchange);
        }

        RequestFingerprint fingerprint = fingerprintFactory.create(exchange);
        RateLimitPolicy policy = policyResolver.resolve(fingerprint);

        return rateLimiter.tryConsume(fingerprint, policy)
                .flatMap(verdict -> {
                    inspectForFraud(fingerprint, verdict);
                    return verdict.allowed()
                            ? admit(exchange, chain, verdict)
                            : reject(exchange, fingerprint, verdict);
                });
    }

    /**
     * Allows the exchange through, attaching advisory headers at commit time.
     *
     * <p>Headers are applied in a {@code beforeCommit} callback rather than
     * eagerly: a downstream handler may clear or replace the response headers,
     * and the commit hook is the last point at which the values are guaranteed
     * to survive to the wire.</p>
     *
     * @param exchange current exchange
     * @param chain    remaining filter chain
     * @param verdict  allow verdict
     * @return completion of the downstream chain
     */
    private Mono<Void> admit(ServerWebExchange exchange, WebFilterChain chain,
                             RateLimitVerdict verdict) {
        exchange.getResponse().beforeCommit(() -> {
            applyQuotaHeaders(exchange.getResponse(), verdict);
            return Mono.empty();
        });
        return chain.filter(exchange);
    }

    /**
     * Short-circuits the chain with a fully formed 429.
     *
     * @param exchange    current exchange
     * @param fingerprint request metadata
     * @param verdict     deny verdict
     * @return completion of the response write
     */
    private Mono<Void> reject(ServerWebExchange exchange, RequestFingerprint fingerprint,
                              RateLimitVerdict verdict) {

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        applyQuotaHeaders(response, verdict);
        response.getHeaders().set(HttpHeaders.RETRY_AFTER, Long.toString(verdict.retryAfterSeconds()));

        if (log.isDebugEnabled()) {
            log.debug("Shedding request [correlationId={}, identity={}, policy={}, path={}, "
                            + "retryAfter={}s]",
                    fingerprint.correlationId(), fingerprint.identity().asKeySegment(),
                    verdict.policyName(), fingerprint.path(), verdict.retryAfterSeconds());
        }

        DataBuffer buffer = response.bufferFactory().wrap(errorBody(fingerprint, verdict));
        return response.writeWith(Mono.just(buffer))
                .doOnError(error -> DataBufferUtils.release(buffer));
    }

    /**
     * Serialises the problem document, degrading to a static body on failure.
     *
     * @param fingerprint request metadata
     * @param verdict     deny verdict
     * @return UTF-8 encoded JSON body
     */
    private byte[] errorBody(RequestFingerprint fingerprint, RateLimitVerdict verdict) {
        RateLimitErrorResponse body = new RateLimitErrorResponse(
                RateLimitErrorResponse.TYPE_RATE_LIMIT_EXCEEDED,
                "Too Many Requests",
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Request quota exhausted for policy '" + verdict.policyName()
                        + "'. Retry after " + verdict.retryAfterSeconds() + " second(s).",
                fingerprint.path(),
                verdict.policyName(),
                verdict.limit(),
                verdict.remaining(),
                verdict.retryAfterSeconds(),
                fingerprint.correlationId(),
                fingerprint.observedAt());

        try {
            return objectMapper.writeValueAsBytes(body);
        } catch (JsonProcessingException cause) {
            log.error("Unable to serialise the rate-limit problem document; "
                    + "falling back to a static body.", cause);
            return FALLBACK_BODY;
        }
    }

    /**
     * Applies the advisory quota headers shared by the allow and deny paths.
     *
     * @param response current response
     * @param verdict  decision to describe
     */
    private void applyQuotaHeaders(ServerHttpResponse response, RateLimitVerdict verdict) {
        HttpHeaders headers = response.getHeaders();
        headers.set(HEADER_LIMIT, Long.toString(verdict.limit()));
        headers.set(HEADER_REMAINING, Long.toString(verdict.remaining()));
        headers.set(HEADER_RESET, Long.toString(verdict.resetAt().getEpochSecond()));
        headers.set(HEADER_POLICY, verdict.policyName());
        if (verdict.degraded()) {
            headers.set(HEADER_DEGRADED, "true");
        }
    }

    /**
     * Fires fraud scoring on a detached subscription.
     *
     * <p>Deliberately not composed into the response pipeline: scoring performs
     * Redis and Kafka I/O, and the customer must not wait for telemetry. The
     * engine absorbs its own failures, so the only error that can reach the
     * handler here is a defect, which is logged rather than swallowed.</p>
     *
     * @param fingerprint request metadata
     * @param verdict     admission decision
     */
    private void inspectForFraud(RequestFingerprint fingerprint, RateLimitVerdict verdict) {
        fraudDetectionEngine.inspect(fingerprint, verdict)
                .subscribe(
                        alert -> { /* already logged and metered by the publisher */ },
                        error -> log.error("Unexpected fraud-engine defect [correlationId={}]",
                                fingerprint.correlationId(), error));
    }
}
