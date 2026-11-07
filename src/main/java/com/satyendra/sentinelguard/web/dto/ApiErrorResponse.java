/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Generic error envelope used for everything other than quota exhaustion.
 *
 * @param status          HTTP status code
 * @param error           reason phrase
 * @param message         human readable summary
 * @param path            request path
 * @param correlationId   correlation id of the exchange
 * @param fieldViolations per-field validation failures, possibly empty
 * @param timestamp       failure instant (UTC)
 * @author Satyendra Singh
 */
public record ApiErrorResponse(
        int status,
        String error,
        String message,
        String path,
        String correlationId,
        Map<String, List<String>> fieldViolations,
        Instant timestamp) {
}
