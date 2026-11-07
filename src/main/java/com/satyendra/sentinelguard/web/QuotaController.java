/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import com.satyendra.sentinelguard.limiter.RateLimitPolicyResolver;
import com.satyendra.sentinelguard.limiter.RateLimiter;
import com.satyendra.sentinelguard.web.dto.QuotaSnapshot;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Self-service quota introspection.
 *
 * <p>Exposing the allowance turns rate limiting from a surprise into a
 * contract: a well behaved integrator paces itself from this endpoint instead
 * of discovering the ceiling through 429s. The response deliberately contains
 * no identity value and no Redis key, only the caller's own figures.</p>
 *
 * @author Satyendra Singh
 */
@RestController
@RequestMapping(path = "/api/v1/sentinel")
public class QuotaController {

    private final RateLimiter rateLimiter;
    private final RateLimitPolicyResolver policyResolver;
    private final RequestFingerprintFactory fingerprintFactory;

    /**
     * @param rateLimiter        distributed token bucket
     * @param policyResolver     policy lookup
     * @param fingerprintFactory exchange to fingerprint mapper
     */
    public QuotaController(RateLimiter rateLimiter,
                           RateLimitPolicyResolver policyResolver,
                           RequestFingerprintFactory fingerprintFactory) {
        this.rateLimiter = rateLimiter;
        this.policyResolver = policyResolver;
        this.fingerprintFactory = fingerprintFactory;
    }

    /**
     * Reports the caller's remaining allowance without charging a token.
     *
     * @param exchange current exchange
     * @return quota snapshot
     */
    @GetMapping("/quota")
    public Mono<QuotaSnapshot> quota(ServerWebExchange exchange) {
        RequestFingerprint fingerprint = fingerprintFactory.create(exchange);
        RateLimitPolicy policy = policyResolver.resolve(fingerprint);

        return rateLimiter.peek(fingerprint, policy)
                .map(verdict -> QuotaSnapshot.from(fingerprint, policy, verdict));
    }
}
