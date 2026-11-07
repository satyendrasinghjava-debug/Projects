/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.limiter;

import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import reactor.core.publisher.Mono;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Admission-control abstraction over a distributed quota store.
 *
 * <p>Implementations must be non-blocking: the returned {@link Mono} is
 * subscribed on a Netty event-loop thread.</p>
 *
 * @author Satyendra Singh
 */
public interface RateLimiter {

    /**
     * Atomically attempts to debit {@link RateLimitPolicy#tokensPerRequest()}
     * tokens from the caller's bucket.
     *
     * @param fingerprint normalised request metadata
     * @param policy      resolved policy to enforce
     * @return verdict; never an error signal, backend failures are translated
     *         into a degraded verdict according to the fail-open setting
     */
    Mono<RateLimitVerdict> tryConsume(RequestFingerprint fingerprint, RateLimitPolicy policy);

    /**
     * Reports the caller's current allowance without charging the request.
     *
     * <p>Implemented as a zero-token consume, so the reported figure is the
     * same number the next real request would see, including lazy refill.</p>
     *
     * @param fingerprint normalised request metadata
     * @param policy      resolved policy to inspect
     * @return non-charging quota snapshot
     */
    Mono<RateLimitVerdict> peek(RequestFingerprint fingerprint, RateLimitPolicy policy);
}
