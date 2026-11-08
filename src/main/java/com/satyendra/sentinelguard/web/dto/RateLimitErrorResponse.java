/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web.dto;

import java.time.Instant;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * RFC 9457 (Problem Details) shaped body returned with HTTP 429.
 *
 * @param type          stable, dereferenceable problem type URI
 * @param title         short, human readable summary
 * @param status        HTTP status code
 * @param detail        actionable explanation for the caller
 * @param instance      request path that was rejected
 * @param policy        policy that rejected the request
 * @param limit         bucket capacity
 * @param remaining     tokens left
 * @param retryAfter    seconds the caller should wait
 * @param correlationId id to quote in a support request
 * @param timestamp     rejection instant (UTC)
 * @author Satyendra Singh
 */
public record RateLimitErrorResponse(
        String type,
        String title,
        int status,
        String detail,
        String instance,
        String policy,
        long limit,
        long remaining,
        long retryAfter,
        String correlationId,
        Instant timestamp) {

    /** Canonical problem type URI for quota exhaustion. */
    public static final String TYPE_RATE_LIMIT_EXCEEDED =
            "https://sentinelguard.satyendra.com/problems/rate-limit-exceeded";
}
