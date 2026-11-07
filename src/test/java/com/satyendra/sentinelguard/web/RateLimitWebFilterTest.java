/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.fraud.FraudDetectionEngine;
import com.satyendra.sentinelguard.limiter.RateLimitPolicyResolver;
import com.satyendra.sentinelguard.limiter.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link RateLimitWebFilter}, exercised against Spring's mock
 * reactive HTTP stack so the real header and body mechanics are covered without
 * starting a server.
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("RateLimitWebFilter")
class RateLimitWebFilterTest {

    private static final Instant NOW = Instant.parse("2026-06-01T09:00:00Z");

    private static final RateLimitPolicy POLICY = new RateLimitPolicy(
            "payments-strict", 20L, 20L, Duration.ofMinutes(1), 1L, Duration.ofMinutes(10));

    @Mock
    private RateLimiter rateLimiter;

    @Mock
    private RateLimitPolicyResolver policyResolver;

    @Mock
    private RequestFingerprintFactory fingerprintFactory;

    @Mock
    private FraudDetectionEngine fraudDetectionEngine;

    private SentinelGuardProperties properties;
    private RateLimitWebFilter filter;
    private final AtomicBoolean chainInvoked = new AtomicBoolean(false);

    /** Commits the response so that {@code beforeCommit} hooks actually run. */
    private final WebFilterChain committingChain = exchange -> {
        chainInvoked.set(true);
        return exchange.getResponse().setComplete();
    };

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        filter = newFilter(new ObjectMapper().findAndRegisterModules());

        doReturn(false).when(policyResolver).isExcluded(any());
        doReturn(POLICY).when(policyResolver).resolve(any());
        doReturn(fingerprint()).when(fingerprintFactory).create(any());
        doReturn(Mono.empty()).when(fraudDetectionEngine).inspect(any(), any());
    }

    // =====================================================================
    // Bypass
    // =====================================================================

    @Test
    @DisplayName("an excluded path never touches the quota backend")
    void excludedPathBypasses() {
        doReturn(true).when(policyResolver).isExcluded("/actuator/health");

        MockServerWebExchange exchange = exchange("/actuator/health");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        assertThat(chainInvoked).isTrue();
        verifyNoInteractions(rateLimiter);
        verifyNoInteractions(fraudDetectionEngine);
    }

    @Test
    @DisplayName("disabling the engine turns the filter into a pass-through")
    void disabledFilterBypasses() {
        properties.getRateLimit().setEnabled(false);

        filter.filter(exchange("/api/v1/transactions"), committingChain).block(Duration.ofSeconds(1));

        assertThat(chainInvoked).isTrue();
        verifyNoInteractions(rateLimiter);
    }

    // =====================================================================
    // Admission
    // =====================================================================

    @Test
    @DisplayName("an admitted request continues the chain with advisory headers")
    void admitsAndDecorates() {
        doReturn(Mono.just(RateLimitVerdict.allow(POLICY, "bucket", 19L, NOW)))
                .when(rateLimiter).tryConsume(any(), eq(POLICY));

        MockServerWebExchange exchange = exchange("/api/v1/transactions");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        assertThat(chainInvoked).isTrue();
        HttpHeaders headers = exchange.getResponse().getHeaders();
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_LIMIT)).isEqualTo("20");
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_REMAINING)).isEqualTo("19");
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_POLICY)).isEqualTo("payments-strict");
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_RESET))
                .isEqualTo(Long.toString(NOW.plus(Duration.ofMinutes(1)).getEpochSecond()));
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_DEGRADED)).isNull();
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isNull();
    }

    @Test
    @DisplayName("a degraded decision is advertised to the caller")
    void advertisesDegradedDecisions() {
        doReturn(Mono.just(RateLimitVerdict.degraded(POLICY, true, NOW)))
                .when(rateLimiter).tryConsume(any(), any());

        MockServerWebExchange exchange = exchange("/api/v1/transactions");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        assertThat(chainInvoked).isTrue();
        assertThat(exchange.getResponse().getHeaders()
                .getFirst(RateLimitWebFilter.HEADER_DEGRADED)).isEqualTo("true");
    }

    // =====================================================================
    // Rejection
    // =====================================================================

    @Test
    @DisplayName("an exhausted quota short-circuits the chain with a complete 429")
    void rejectsWithProblemDetail() {
        doReturn(Mono.just(RateLimitVerdict.deny(POLICY, "bucket", 0L, Duration.ofSeconds(12), NOW)))
                .when(rateLimiter).tryConsume(any(), any());

        MockServerWebExchange exchange = exchange("/api/v1/transactions");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        // The handler must never run for a shed request.
        assertThat(chainInvoked).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        HttpHeaders headers = exchange.getResponse().getHeaders();
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("12");
        assertThat(headers.getFirst(RateLimitWebFilter.HEADER_REMAINING)).isEqualTo("0");

        String body = exchange.getResponse().getBodyAsString().block(Duration.ofSeconds(1));
        assertThat(body)
                .contains("\"status\":429")
                .contains("\"policy\":\"payments-strict\"")
                .contains("\"retryAfter\":12")
                .contains("\"correlationId\":\"corr-42\"")
                .contains("rate-limit-exceeded");
    }

    @Test
    @DisplayName("a body-serialisation defect still produces a valid 429, never an empty one")
    void fallsBackToStaticBody() throws JsonProcessingException {
        ObjectMapper failing = org.mockito.Mockito.mock(ObjectMapper.class);
        doThrow(new JsonProcessingException("boom") { })
                .when(failing).writeValueAsBytes(any());
        filter = newFilter(failing);

        doReturn(Mono.just(RateLimitVerdict.deny(POLICY, "bucket", 0L, Duration.ofSeconds(1), NOW)))
                .when(rateLimiter).tryConsume(any(), any());

        MockServerWebExchange exchange = exchange("/api/v1/transactions");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getBodyAsString().block(Duration.ofSeconds(1)))
                .contains("Too Many Requests");
    }

    // =====================================================================
    // Fraud side channel
    // =====================================================================

    @Test
    @DisplayName("every decision is handed to the fraud engine, allow or deny")
    void feedsTheFraudEngine() {
        doReturn(Mono.just(RateLimitVerdict.allow(POLICY, "bucket", 19L, NOW)))
                .when(rateLimiter).tryConsume(any(), any());
        filter.filter(exchange("/api/v1/transactions"), committingChain).block(Duration.ofSeconds(1));

        doReturn(Mono.just(RateLimitVerdict.deny(POLICY, "bucket", 0L, Duration.ofSeconds(5), NOW)))
                .when(rateLimiter).tryConsume(any(), any());
        filter.filter(exchange("/api/v1/transactions"), committingChain).block(Duration.ofSeconds(1));

        verify(fraudDetectionEngine, org.mockito.Mockito.times(2)).inspect(any(), any());
    }

    @Test
    @DisplayName("a fraud-engine defect never breaks the response")
    void absorbsFraudEngineDefects() {
        doReturn(Mono.error(new IllegalStateException("defect")))
                .when(fraudDetectionEngine).inspect(any(), any());
        doReturn(Mono.just(RateLimitVerdict.allow(POLICY, "bucket", 19L, NOW)))
                .when(rateLimiter).tryConsume(any(), any());

        MockServerWebExchange exchange = exchange("/api/v1/transactions");
        filter.filter(exchange, committingChain).block(Duration.ofSeconds(1));

        assertThat(chainInvoked).isTrue();
        verify(rateLimiter, never()).peek(any(), any());
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private RateLimitWebFilter newFilter(ObjectMapper objectMapper) {
        return new RateLimitWebFilter(rateLimiter, policyResolver, fingerprintFactory,
                fraudDetectionEngine, properties, objectMapper);
    }

    private static MockServerWebExchange exchange(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.post(path).build());
    }

    private static RequestFingerprint fingerprint() {
        return new RequestFingerprint("corr-42",
                new ClientIdentity("digest", IdentityType.API_KEY), "203.0.113.4",
                "POST", "/api/v1/transactions", "Mozilla/5.0", NOW);
    }
}
