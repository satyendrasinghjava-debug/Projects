/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.limiter.RateLimitPolicyResolver;
import com.satyendra.sentinelguard.limiter.RateLimiter;
import com.satyendra.sentinelguard.web.dto.TransactionRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.test.StepVerifier;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static reactor.core.publisher.Mono.just;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for the HTTP handlers.
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("HTTP handlers")
class ControllerTest {

    private static final Instant NOW = Instant.parse("2026-09-09T09:09:09Z");

    private static final RateLimitPolicy POLICY = new RateLimitPolicy(
            "standard", 100L, 100L, Duration.ofMinutes(1), 1L, Duration.ofMinutes(10));

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @Mock
    private RateLimiter rateLimiter;

    @Mock
    private RateLimitPolicyResolver policyResolver;

    @Mock
    private RequestFingerprintFactory fingerprintFactory;

    @Test
    @DisplayName("accepting a transaction echoes the reference and the correlation id")
    void acceptsTransaction() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/transactions").build());
        exchange.getAttributes().put(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE, "corr-1");

        TransactionRequest request = new TransactionRequest(
                "ref-001", new BigDecimal("125.50"), "USD", "ACC-998877");

        StepVerifier.create(new TransactionController(clock).submit(request, exchange))
                .assertNext(response -> {
                    assertThat(response.reference()).isEqualTo("ref-001");
                    assertThat(response.amount()).isEqualByComparingTo("125.50");
                    assertThat(response.currency()).isEqualTo("USD");
                    assertThat(response.status()).isEqualTo("ACCEPTED");
                    assertThat(response.correlationId()).isEqualTo("corr-1");
                    assertThat(response.transactionId()).isNotBlank();
                    assertThat(response.acceptedAt()).isEqualTo(NOW);
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("a lookup without a correlation id reports it as unavailable")
    void lookupWithoutCorrelationId() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/transactions/ref-7").build());

        StepVerifier.create(new TransactionController(clock)
                        .findByReference("ref-7", exchange))
                .assertNext(response -> {
                    assertThat(response.reference()).isEqualTo("ref-7");
                    assertThat(response.status()).isEqualTo("SETTLED");
                    assertThat(response.correlationId()).isEqualTo("unavailable");
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("the quota endpoint peeks without charging a token and hides internals")
    void quotaSnapshotDoesNotCharge() {
        RequestFingerprint fingerprint = new RequestFingerprint("corr-2",
                new ClientIdentity("digest", IdentityType.API_KEY), "203.0.113.1",
                "GET", "/api/v1/sentinel/quota", "JUnit", NOW);

        doReturn(fingerprint).when(fingerprintFactory).create(any());
        doReturn(POLICY).when(policyResolver).resolve(any());
        doReturn(just(RateLimitVerdict.allow(POLICY, "bucket-key-should-not-leak", 97L, NOW)))
                .when(rateLimiter).peek(any(), any());

        QuotaController controller =
                new QuotaController(rateLimiter, policyResolver, fingerprintFactory);

        StepVerifier.create(controller.quota(MockServerWebExchange.from(
                        MockServerHttpRequest.get("/api/v1/sentinel/quota").build())))
                .assertNext(snapshot -> {
                    assertThat(snapshot.remaining()).isEqualTo(97L);
                    assertThat(snapshot.limit()).isEqualTo(100L);
                    assertThat(snapshot.policy()).isEqualTo("standard");
                    assertThat(snapshot.identityType()).isEqualTo(IdentityType.API_KEY);
                    assertThat(snapshot.sustainedRatePerSecond()).isGreaterThan(1.0d);
                    assertThat(snapshot.degraded()).isFalse();
                    assertThat(snapshot.resetAt()).isEqualTo(NOW.plus(Duration.ofMinutes(1)));
                })
                .verifyComplete();
    }
}
