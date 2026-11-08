/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link CorrelationIdWebFilter}.
 *
 * @author Satyendra Singh
 */
@DisplayName("CorrelationIdWebFilter")
class CorrelationIdWebFilterTest {

    private SentinelGuardProperties properties;
    private CorrelationIdWebFilter filter;

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        filter = new CorrelationIdWebFilter(properties);
    }

    @Test
    @DisplayName("honours an id supplied by an upstream gateway")
    void honoursInboundId() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/transactions")
                        .header("X-Correlation-Id", " trace-123 ")
                        .build());

        filter.filter(exchange, noOpChain()).block(Duration.ofSeconds(1));

        // The cast is required: ServerWebExchange.getAttribute is <T> T, so without
        // a target type AssertJ cannot choose between its Predicate overloads.
        assertThat((String) exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE))
                .isEqualTo("trace-123");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isEqualTo("trace-123");
    }

    @Test
    @DisplayName("mints an id when none is supplied, and echoes it back")
    void mintsMissingId() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/transactions").build());

        filter.filter(exchange, noOpChain()).block(Duration.ofSeconds(1));

        String minted = exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE);
        assertThat(minted).isNotBlank();
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Correlation-Id"))
                .isEqualTo(minted);
    }

    @Test
    @DisplayName("a blank inbound id is replaced rather than propagated")
    void replacesBlankId() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/a").header("X-Correlation-Id", "   ").build());

        filter.filter(exchange, noOpChain()).block(Duration.ofSeconds(1));

        assertThat((String) exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE))
                .isNotBlank()
                .isNotEqualTo("   ");
    }

    @Test
    @DisplayName("publishes the id into the Reactor context for downstream operators")
    void publishesToReactorContext() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/a").header("X-Correlation-Id", "trace-9").build());
        AtomicReference<String> seen = new AtomicReference<>();

        WebFilterChain contextReadingChain = ex -> Mono.deferContextual(context -> {
            seen.set(context.get(CorrelationIdWebFilter.CORRELATION_ID_CONTEXT_KEY));
            return Mono.empty();
        });

        filter.filter(exchange, contextReadingChain).block(Duration.ofSeconds(1));

        assertThat(seen.get()).isEqualTo("trace-9");
    }

    @Test
    @DisplayName("a custom correlation header name is honoured")
    void customHeaderName() {
        properties.getIdentity().setCorrelationHeader("X-Request-Id");
        filter = new CorrelationIdWebFilter(properties);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/a").header("X-Request-Id", "req-1").build());

        filter.filter(exchange, noOpChain()).block(Duration.ofSeconds(1));

        assertThat(exchange.getResponse().getHeaders().getFirst("X-Request-Id")).isEqualTo("req-1");
    }

    private static WebFilterChain noOpChain() {
        return exchange -> Mono.empty();
    }
}
