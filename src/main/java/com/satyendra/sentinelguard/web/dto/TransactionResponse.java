/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web.dto;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Outcome of an accepted transaction.
 *
 * @param transactionId server assigned identifier
 * @param reference     caller supplied reference, echoed back
 * @param amount        accepted amount
 * @param currency      accepted currency
 * @param status        lifecycle status
 * @param correlationId correlation id of the exchange
 * @param acceptedAt    acceptance instant (UTC)
 * @author Satyendra Singh
 */
public record TransactionResponse(
        String transactionId,
        String reference,
        BigDecimal amount,
        String currency,
        String status,
        String correlationId,
        Instant acceptedAt) {
}
