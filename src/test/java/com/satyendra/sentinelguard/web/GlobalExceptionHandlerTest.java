/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.web.dto.ApiErrorResponse;
import com.satyendra.sentinelguard.web.dto.TransactionRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebInputException;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link GlobalExceptionHandler}.
 *
 * @author Satyendra Singh
 */
@DisplayName("GlobalExceptionHandler")
class GlobalExceptionHandlerTest {

    private static final Instant NOW = Instant.parse("2026-08-08T08:08:08Z");

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler(Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("reports every field violation so the caller can fix the payload")
    void reportsFieldViolations() throws NoSuchMethodException {
        Method method = Sample.class.getDeclaredMethod("submit", TransactionRequest.class);
        BeanPropertyBindingResult binding =
                new BeanPropertyBindingResult(new Object(), "transactionRequest");
        binding.addError(new FieldError("transactionRequest", "currency",
                "currency must be a 3-letter ISO-4217 code"));
        binding.addError(new FieldError("transactionRequest", "amount",
                "amount must be at least 0.01"));

        ResponseEntity<ApiErrorResponse> response = handler.handleInvalidInput(
                new WebExchangeBindException(new MethodParameter(method, 0), binding),
                exchange());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ApiErrorResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.message()).isEqualTo("Request validation failed.");
        assertThat(body.fieldViolations())
                .containsEntry("currency", java.util.List.of("currency must be a 3-letter ISO-4217 code"))
                .containsEntry("amount", java.util.List.of("amount must be at least 0.01"));
        assertThat(body.correlationId()).isEqualTo("corr-55");
        assertThat(body.timestamp()).isEqualTo(NOW);
        assertThat(body.path()).isEqualTo("/api/v1/transactions");
    }

    @Test
    @DisplayName("a malformed body without field errors still yields a structured 400")
    void handlesMalformedBody() {
        ResponseEntity<ApiErrorResponse> response = handler.handleInvalidInput(
                new ServerWebInputException("Failed to read HTTP message"), exchange());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().message()).isEqualTo("Malformed request payload.");
        assertThat(response.getBody().fieldViolations()).isEmpty();
    }

    @Test
    @DisplayName("an intentional status exception keeps its status and reason")
    void preservesStatusExceptions() {
        ResponseEntity<ApiErrorResponse> response = handler.handleStatusException(
                new ResponseStatusException(HttpStatus.NOT_FOUND, "transaction not found"),
                exchange());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().message()).isEqualTo("transaction not found");
        assertThat(response.getBody().status()).isEqualTo(404);
    }

    @Test
    @DisplayName("a status exception without a reason falls back to the reason phrase")
    void defaultsMissingReason() {
        ResponseEntity<ApiErrorResponse> response = handler.handleStatusException(
                new ResponseStatusException(HttpStatus.CONFLICT), exchange());

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().message()).isEqualTo("Conflict");
    }

    @Test
    @DisplayName("an unexpected fault never leaks internals to the caller")
    void hidesInternals() {
        ResponseEntity<ApiErrorResponse> response = handler.handleUnexpected(
                new IllegalStateException("jdbc url user=admin password=hunter2"), exchange());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().message())
                .doesNotContain("hunter2")
                .contains("correlation id");
    }

    @Test
    @DisplayName("falls back to 'unavailable' when no correlation id was established")
    void correlationIdFallback() {
        MockServerWebExchange bare = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/transactions").build());

        ResponseEntity<ApiErrorResponse> response =
                handler.handleUnexpected(new RuntimeException("boom"), bare);

        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().correlationId()).isEqualTo("unavailable");
    }

    private static MockServerWebExchange exchange() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/transactions").build());
        exchange.getAttributes().put(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE, "corr-55");
        return exchange;
    }

    /** Only used to obtain a realistic {@link MethodParameter} for the binding exception. */
    private static final class Sample {
        @SuppressWarnings("unused")
        void submit(TransactionRequest request) {
            // no-op
        }
    }
}
