/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Establishes an end-to-end correlation id and echoes it back to the caller.
 *
 * <p>Runs first in the chain so that every rate-limit rejection and every fraud
 * alert carries the same id as the access log line, which is what makes a
 * 429 reported by a customer traceable to the alert it produced.</p>
 *
 * <p>An inbound id is honoured when present (distributed tracing from an
 * upstream gateway) and minted otherwise.</p>
 *
 * @author Satyendra Singh
 */
@Component
@Order(CorrelationIdWebFilter.ORDER)
public class CorrelationIdWebFilter implements WebFilter {

    /** Runs ahead of every other SentinelGuard filter. */
    public static final int ORDER = -200;

    /** Exchange attribute under which the id is published. */
    public static final String CORRELATION_ID_ATTRIBUTE = "sentinelguard.correlationId";

    /** Reactor context key, so reactive operators downstream can log the id. */
    public static final String CORRELATION_ID_CONTEXT_KEY = "correlationId";

    private final String correlationHeader;

    /**
     * @param properties engine configuration
     */
    public CorrelationIdWebFilter(SentinelGuardProperties properties) {
        this.correlationHeader = properties.getIdentity().getCorrelationHeader();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String inbound = exchange.getRequest().getHeaders().getFirst(correlationHeader);
        String correlationId = (inbound == null || inbound.isBlank())
                ? UUID.randomUUID().toString()
                : inbound.trim();

        exchange.getAttributes().put(CORRELATION_ID_ATTRIBUTE, correlationId);
        exchange.getResponse().getHeaders().set(correlationHeader, correlationId);

        return chain.filter(exchange)
                .contextWrite(context -> context.put(CORRELATION_ID_CONTEXT_KEY, correlationId));
    }
}
