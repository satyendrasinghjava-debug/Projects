/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.web.dto.ApiErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Uniform error contract for everything the rate-limit filter does not handle
 * itself.
 *
 * <p>Two rules are enforced here. Client faults are reported with their precise
 * field violations, because a 400 that does not say what was wrong generates a
 * support ticket. Server faults are logged with their stack trace and
 * correlation id but answered with a generic message, because exception text
 * leaks internals to an attacker who is probing the surface.</p>
 *
 * @author Satyendra Singh
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final Clock clock;

    /**
     * @param clock UTC clock
     */
    public GlobalExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    /**
     * Handles payload binding and bean-validation failures.
     *
     * @param exception the binding failure
     * @param exchange  current exchange
     * @return 400 with per-field violations
     */
    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidInput(ServerWebInputException exception,
                                                               ServerWebExchange exchange) {
        Map<String, List<String>> violations = new LinkedHashMap<>();

        if (exception instanceof WebExchangeBindException binding) {
            for (FieldError fieldError : binding.getFieldErrors()) {
                violations.computeIfAbsent(fieldError.getField(), key -> new ArrayList<>())
                        .add(fieldError.getDefaultMessage());
            }
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiErrorResponse(
                        HttpStatus.BAD_REQUEST.value(),
                        HttpStatus.BAD_REQUEST.getReasonPhrase(),
                        violations.isEmpty() ? "Malformed request payload." : "Request validation failed.",
                        exchange.getRequest().getPath().value(),
                        correlationId(exchange),
                        violations,
                        Instant.now(clock)));
    }

    /**
     * Preserves intentional status exceptions raised by handlers.
     *
     * @param exception the status exception
     * @param exchange  current exchange
     * @return the requested status with a structured body
     */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiErrorResponse> handleStatusException(ResponseStatusException exception,
                                                                  ServerWebExchange exchange) {
        HttpStatus status = HttpStatus.resolve(exception.getStatusCode().value());
        HttpStatus resolved = status != null ? status : HttpStatus.INTERNAL_SERVER_ERROR;

        return ResponseEntity.status(resolved)
                .body(new ApiErrorResponse(
                        resolved.value(),
                        resolved.getReasonPhrase(),
                        exception.getReason() != null ? exception.getReason() : resolved.getReasonPhrase(),
                        exchange.getRequest().getPath().value(),
                        correlationId(exchange),
                        Map.of(),
                        Instant.now(clock)));
    }

    /**
     * Last-resort handler for unexpected faults.
     *
     * @param exception the fault
     * @param exchange  current exchange
     * @return 500 with a deliberately generic message
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception exception,
                                                             ServerWebExchange exchange) {
        String correlationId = correlationId(exchange);
        log.error("Unhandled failure while serving {} {} [correlationId={}]",
                exchange.getRequest().getMethod(), exchange.getRequest().getPath().value(),
                correlationId, exception);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiErrorResponse(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                        "An unexpected error occurred. Quote the correlation id when reporting it.",
                        exchange.getRequest().getPath().value(),
                        correlationId,
                        Map.of(),
                        Instant.now(clock)));
    }

    private static String correlationId(ServerWebExchange exchange) {
        Object attribute = exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE);
        return attribute instanceof String correlationId ? correlationId : "unavailable";
    }
}
