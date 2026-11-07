/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Outcome of one admission decision, carrying everything the HTTP layer needs
 * to emit standards-aligned rate-limit headers without recomputing anything.
 *
 * @param allowed     whether the request may proceed (tokens already debited)
 * @param policyName  policy that produced this verdict
 * @param bucketKey   Redis key of the bucket consulted
 * @param limit       bucket capacity
 * @param remaining   tokens left after this decision
 * @param retryAfter  wait hint; {@link Duration#ZERO} when allowed
 * @param resetAt     instant at which the bucket is expected to admit again
 * @param degraded    {@code true} when Redis was unreachable and a fail-open or
 *                    fail-closed fallback produced this verdict
 * @author Satyendra Singh
 */
public record RateLimitVerdict(
        boolean allowed,
        String policyName,
        String bucketKey,
        long limit,
        long remaining,
        Duration retryAfter,
        Instant resetAt,
        boolean degraded) {

    public RateLimitVerdict {
        Objects.requireNonNull(policyName, "policyName must not be null");
        Objects.requireNonNull(bucketKey, "bucketKey must not be null");
        Objects.requireNonNull(retryAfter, "retryAfter must not be null");
        Objects.requireNonNull(resetAt, "resetAt must not be null");
    }

    /**
     * Builds an allow verdict.
     *
     * @param policy    policy applied
     * @param bucketKey bucket consulted
     * @param remaining tokens left
     * @param now       decision instant
     * @return immutable allow verdict
     */
    public static RateLimitVerdict allow(RateLimitPolicy policy, String bucketKey,
                                         long remaining, Instant now) {
        return new RateLimitVerdict(true, policy.name(), bucketKey, policy.capacity(),
                remaining, Duration.ZERO, now.plus(policy.refillPeriod()), false);
    }

    /**
     * Builds a deny verdict.
     *
     * @param policy     policy applied
     * @param bucketKey  bucket consulted
     * @param remaining  tokens left (typically below {@code tokensPerRequest})
     * @param retryAfter precise replenishment wait computed by the Lua script
     * @param now        decision instant
     * @return immutable deny verdict
     */
    public static RateLimitVerdict deny(RateLimitPolicy policy, String bucketKey,
                                        long remaining, Duration retryAfter, Instant now) {
        return new RateLimitVerdict(false, policy.name(), bucketKey, policy.capacity(),
                remaining, retryAfter, now.plus(retryAfter), false);
    }

    /**
     * Builds the verdict used when the Redis backend could not be consulted.
     *
     * @param policy   policy applied
     * @param failOpen {@code true} to admit traffic, {@code false} to shed it
     * @param now      decision instant
     * @return immutable degraded verdict
     */
    public static RateLimitVerdict degraded(RateLimitPolicy policy, boolean failOpen, Instant now) {
        Duration retryAfter = failOpen ? Duration.ZERO : policy.refillPeriod();
        return new RateLimitVerdict(failOpen, policy.name(), "unavailable", policy.capacity(),
                failOpen ? policy.capacity() : 0L, retryAfter, now.plus(retryAfter), true);
    }

    /** @return {@code Retry-After} value in whole seconds, rounded up, never negative */
    public long retryAfterSeconds() {
        long millis = retryAfter.toMillis();
        return millis <= 0 ? 0L : (millis + 999L) / 1000L;
    }
}
