/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link RequestFingerprintFactory}.
 *
 * @author Satyendra Singh
 */
@DisplayName("RequestFingerprintFactory")
class RequestFingerprintFactoryTest {

    private static final Instant NOW = Instant.parse("2026-07-07T07:07:07Z");

    private RequestFingerprintFactory factory;

    @BeforeEach
    void setUp() {
        SentinelGuardProperties properties = new SentinelGuardProperties();
        factory = new RequestFingerprintFactory(new ClientIdentityResolver(properties),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("captures method, path, agent, identity and the correlation id")
    void capturesMetadata() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/transactions?dryRun=true")
                        .header("X-API-Key", "key-1")
                        .header(HttpHeaders.USER_AGENT, "JUnit/5")
                        .remoteAddress(new InetSocketAddress("203.0.113.9", 8443))
                        .build());
        exchange.getAttributes()
                .put(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE, "corr-abc");

        RequestFingerprint fingerprint = factory.create(exchange);

        assertThat(fingerprint.correlationId()).isEqualTo("corr-abc");
        assertThat(fingerprint.httpMethod()).isEqualTo("POST");
        // The query string must not be part of the path, or every distinct query
        // would look like a separate endpoint to the enumeration heuristic.
        assertThat(fingerprint.path()).isEqualTo("/api/v1/transactions");
        assertThat(fingerprint.userAgent()).isEqualTo("JUnit/5");
        assertThat(fingerprint.hasUserAgent()).isTrue();
        assertThat(fingerprint.identity().type()).isEqualTo(IdentityType.API_KEY);
        assertThat(fingerprint.clientIp()).isEqualTo("203.0.113.9");
        assertThat(fingerprint.observedAt()).isEqualTo(NOW);
    }

    @Test
    @DisplayName("mints a correlation id when used outside the correlation filter")
    void mintsCorrelationIdWhenAbsent() {
        RequestFingerprint fingerprint = factory.create(MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/sentinel/quota").build()));

        assertThat(fingerprint.correlationId()).isNotBlank();
        assertThat(fingerprint.identity().type()).isEqualTo(IdentityType.ANONYMOUS);
        assertThat(fingerprint.hasUserAgent()).isFalse();
        assertThat(fingerprint.clientIp()).isEqualTo("unknown");
    }

    @Test
    @DisplayName("ignores a non-string correlation attribute")
    void ignoresNonStringAttribute() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/a").build());
        exchange.getAttributes().put(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE, 42);

        assertThat(factory.create(exchange).correlationId()).isNotBlank();
    }
}
