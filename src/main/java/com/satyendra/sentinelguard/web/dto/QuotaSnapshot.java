/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web.dto;

import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;

import java.time.Instant;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Non-charging view of a caller's current allowance, so a well behaved client
 * can pace itself instead of discovering the limit by being rejected.
 *
 * @param identityType          how the caller was identified
 * @param policy                governing policy name
 * @param limit                 bucket capacity
 * @param remaining             tokens currently available
 * @param sustainedRatePerSecond long-run admission rate
 * @param resetAt               next replenishment instant
 * @param degraded              {@code true} when the quota backend was unreachable
 * @author Satyendra Singh
 */
public record QuotaSnapshot(
        IdentityType identityType,
        String policy,
        long limit,
        long remaining,
        double sustainedRatePerSecond,
        Instant resetAt,
        boolean degraded) {

    /**
     * @param fingerprint request metadata
     * @param policy      policy in force
     * @param verdict     non-charging verdict produced by a peek
     * @return projection safe to return to the caller (no identity value, no keys)
     */
    public static QuotaSnapshot from(RequestFingerprint fingerprint, RateLimitPolicy policy,
                                     RateLimitVerdict verdict) {
        return new QuotaSnapshot(
                fingerprint.identity().type(),
                policy.name(),
                verdict.limit(),
                verdict.remaining(),
                policy.sustainedRatePerSecond(),
                verdict.resetAt(),
                verdict.degraded());
    }
}
