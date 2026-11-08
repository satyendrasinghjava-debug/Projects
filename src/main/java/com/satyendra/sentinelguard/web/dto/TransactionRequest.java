/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Inbound payload of the protected demonstration endpoint.
 *
 * @param reference   caller supplied idempotency reference
 * @param amount      transaction amount, two decimal places
 * @param currency    ISO-4217 alphabetic code
 * @param beneficiary beneficiary account identifier
 * @author Satyendra Singh
 */
public record TransactionRequest(

        @NotBlank(message = "reference is required")
        @Size(max = 64, message = "reference must not exceed 64 characters")
        String reference,

        @NotNull(message = "amount is required")
        @DecimalMin(value = "0.01", message = "amount must be at least 0.01")
        @Digits(integer = 15, fraction = 2, message = "amount must have at most 2 decimal places")
        BigDecimal amount,

        @NotBlank(message = "currency is required")
        @Pattern(regexp = "^[A-Z]{3}$", message = "currency must be a 3-letter ISO-4217 code")
        String currency,

        @NotBlank(message = "beneficiary is required")
        @Size(max = 64, message = "beneficiary must not exceed 64 characters")
        String beneficiary) {
}
