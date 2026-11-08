/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.web.dto.TransactionRequest;
import com.satyendra.sentinelguard.web.dto.TransactionResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Protected business endpoints used to exercise the engine end to end.
 *
 * <p>Note what is <em>absent</em>: there is no rate-limit annotation, no
 * interceptor registration and no quota bookkeeping. Admission control is a
 * platform concern applied by {@link RateLimitWebFilter} before routing, so a
 * handler stays a handler. Adding a new endpoint protects it automatically.</p>
 *
 * @author Satyendra Singh
 */
@RestController
@RequestMapping(path = "/api/v1/transactions")
public class TransactionController {

    private final Clock clock;

    /**
     * @param clock UTC clock
     */
    public TransactionController(Clock clock) {
        this.clock = clock;
    }

    /**
     * Accepts a transaction.
     *
     * @param request  validated payload
     * @param exchange current exchange, for correlation id echo
     * @return the accepted transaction
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<TransactionResponse> submit(@Valid @RequestBody TransactionRequest request,
                                            ServerWebExchange exchange) {
        return Mono.fromSupplier(() -> new TransactionResponse(
                UUID.randomUUID().toString(),
                request.reference(),
                request.amount(),
                request.currency(),
                "ACCEPTED",
                correlationId(exchange),
                Instant.now(clock)));
    }

    /**
     * Looks a transaction up by reference.
     *
     * @param reference caller supplied reference
     * @param exchange  current exchange, for correlation id echo
     * @return the transaction projection
     */
    @GetMapping("/{reference}")
    public Mono<TransactionResponse> findByReference(@PathVariable String reference,
                                                     ServerWebExchange exchange) {
        return Mono.fromSupplier(() -> new TransactionResponse(
                UUID.nameUUIDFromBytes(reference.getBytes(StandardCharsets.UTF_8)).toString(),
                reference,
                new BigDecimal("0.00"),
                "USD",
                "SETTLED",
                correlationId(exchange),
                Instant.now(clock)));
    }

    private static String correlationId(ServerWebExchange exchange) {
        Object attribute = exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE);
        return attribute instanceof String correlationId ? correlationId : "unavailable";
    }
}
