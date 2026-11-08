/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Normalised, immutable snapshot of the request metadata the engine reasons
 * about. Extracting this at the edge of the filter keeps every downstream
 * component free of {@code ServerWebExchange}, which is what makes the limiter
 * and the fraud engine unit-testable without a mock HTTP stack.
 *
 * @param correlationId end-to-end correlation id
 * @param identity      identity the quota is charged to
 * @param clientIp      best-effort source address
 * @param httpMethod    HTTP method
 * @param path          request path, already normalised
 * @param userAgent     reported {@code User-Agent}, or {@code null} when absent
 * @param observedAt    instant the request entered the filter chain
 * @author Satyendra Singh
 */
public record RequestFingerprint(
        String correlationId,
        ClientIdentity identity,
        String clientIp,
        String httpMethod,
        String path,
        String userAgent,
        Instant observedAt) {

    public RequestFingerprint {
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(identity, "identity must not be null");
        Objects.requireNonNull(httpMethod, "httpMethod must not be null");
        Objects.requireNonNull(path, "path must not be null");
        Objects.requireNonNull(observedAt, "observedAt must not be null");
        clientIp = (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp;
    }

    /** @return {@code true} when a non-blank {@code User-Agent} was supplied */
    public boolean hasUserAgent() {
        return userAgent != null && !userAgent.isBlank();
    }
}
