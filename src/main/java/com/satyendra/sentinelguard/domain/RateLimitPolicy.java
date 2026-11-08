/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

import java.time.Duration;
import java.util.Objects;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Fully resolved token-bucket policy. Instances are immutable and safe to share
 * across every event-loop thread.
 *
 * @param name             human readable policy name, surfaced in metrics and alerts
 * @param capacity         bucket size, i.e. the maximum tolerated burst
 * @param refillTokens     tokens credited once per {@code refillPeriod}
 * @param refillPeriod     length of a single refill interval
 * @param tokensPerRequest cost charged for one request
 * @param bucketTtl        idle expiry applied to the Redis bucket key
 * @author Satyendra Singh
 */
public record RateLimitPolicy(
        String name,
        long capacity,
        long refillTokens,
        Duration refillPeriod,
        long tokensPerRequest,
        Duration bucketTtl) {

    /**
     * @throws IllegalArgumentException when the policy could not possibly admit traffic
     */
    public RateLimitPolicy {
        Objects.requireNonNull(name, "policy name must not be null");
        Objects.requireNonNull(refillPeriod, "refillPeriod must not be null");
        Objects.requireNonNull(bucketTtl, "bucketTtl must not be null");
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be > 0 for policy " + name);
        }
        if (refillTokens <= 0) {
            throw new IllegalArgumentException("refillTokens must be > 0 for policy " + name);
        }
        if (refillPeriod.isZero() || refillPeriod.isNegative()) {
            throw new IllegalArgumentException("refillPeriod must be positive for policy " + name);
        }
        if (bucketTtl.isZero() || bucketTtl.isNegative()) {
            throw new IllegalArgumentException("bucketTtl must be positive for policy " + name);
        }
        if (tokensPerRequest <= 0) {
            throw new IllegalArgumentException("tokensPerRequest must be > 0 for policy " + name);
        }
        if (tokensPerRequest > capacity) {
            throw new IllegalArgumentException(
                    "tokensPerRequest (" + tokensPerRequest + ") exceeds capacity (" + capacity
                            + ") for policy " + name + ": every request would be rejected");
        }
    }

    /** @return refill interval expressed in milliseconds, as required by the Lua script */
    public long refillPeriodMillis() {
        return refillPeriod.toMillis();
    }

    /** @return bucket idle expiry expressed in milliseconds */
    public long bucketTtlMillis() {
        return bucketTtl.toMillis();
    }

    /** @return sustained admission rate in requests per second, for dashboards */
    public double sustainedRatePerSecond() {
        return (refillTokens / (double) tokensPerRequest)
                / (refillPeriodMillis() / 1000.0d);
    }
}
