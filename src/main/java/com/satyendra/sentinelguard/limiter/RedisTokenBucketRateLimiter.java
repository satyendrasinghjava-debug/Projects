/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.limiter;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Distributed token bucket backed by a single atomic Redis Lua script.
 *
 * <h3>Why Lua and not WATCH/MULTI or a lock</h3>
 * A naive limiter reads the bucket, computes a refill, then writes it back.
 * With <em>N</em> service replicas that sequence interleaves and tokens are
 * handed out twice (lost update), which is exactly how "rate limited" services
 * still get flattened by a burst. Redis evaluates a Lua script as one
 * indivisible unit on its single command thread, so the read-modify-write
 * cycle here is serialised globally without optimistic retries, without a
 * distributed lock, and in one network round trip.
 *
 * <h3>Redis Cluster safety</h3>
 * The script touches exactly one key, therefore every invocation is trivially
 * single-slot and routable by a cluster client with no hash-tag gymnastics.
 *
 * <h3>Failure policy</h3>
 * Backend faults never propagate to the caller as an error signal. They are
 * converted into a degraded verdict governed by
 * {@code sentinelguard.rate-limit.fail-open}:
 * availability-first deployments admit the request, protection-first
 * deployments (payments, auth) shed it. Either way the event is counted and
 * logged so the choice is observable rather than silent.
 *
 * @author Satyendra Singh
 */
@Component
public class RedisTokenBucketRateLimiter implements RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RedisTokenBucketRateLimiter.class);

    /** Number of elements the Lua program is contracted to return. */
    static final int EXPECTED_REPLY_ARITY = 4;

    private static final String DECISION_METRIC = "sentinelguard.ratelimit.decisions";
    private static final String LATENCY_METRIC = "sentinelguard.ratelimit.backend.latency";

    private final ReactiveStringRedisTemplate redisTemplate;
    private final RedisScript<List<Long>> tokenBucketScript;
    private final SentinelGuardProperties properties;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    /**
     * @param redisTemplate     reactive Redis template (Lettuce, shared event loop)
     * @param tokenBucketScript SHA-cached token-bucket program
     * @param properties        engine configuration
     * @param meterRegistry     Micrometer registry
     * @param clock             UTC clock supplying the refill timestamp
     */
    public RedisTokenBucketRateLimiter(ReactiveStringRedisTemplate redisTemplate,
                                       RedisScript<List<Long>> tokenBucketScript,
                                       SentinelGuardProperties properties,
                                       MeterRegistry meterRegistry,
                                       Clock clock) {
        this.redisTemplate = redisTemplate;
        this.tokenBucketScript = tokenBucketScript;
        this.properties = properties;
        this.meterRegistry = meterRegistry;
        this.clock = clock;
    }

    @Override
    public Mono<RateLimitVerdict> tryConsume(RequestFingerprint fingerprint, RateLimitPolicy policy) {
        return evaluate(fingerprint, policy, policy.tokensPerRequest());
    }

    @Override
    public Mono<RateLimitVerdict> peek(RequestFingerprint fingerprint, RateLimitPolicy policy) {
        // A zero-cost evaluation still triggers the lazy refill inside the
        // script, so the snapshot matches what the next charged request sees.
        return evaluate(fingerprint, policy, 0L);
    }

    /**
     * Single code path shared by {@link #tryConsume} and {@link #peek}.
     *
     * @param fingerprint request metadata
     * @param policy      policy to apply
     * @param cost        tokens to debit (0 for a snapshot)
     * @return verdict mono that never errors
     */
    private Mono<RateLimitVerdict> evaluate(RequestFingerprint fingerprint,
                                            RateLimitPolicy policy,
                                            long cost) {
        final Instant now = Instant.now(clock);
        final String bucketKey = bucketKey(policy, fingerprint);
        final long startedAt = System.nanoTime();

        final List<String> keys = List.of(bucketKey);
        final List<String> args = List.of(
                Long.toString(policy.capacity()),
                Long.toString(policy.refillTokens()),
                Long.toString(policy.refillPeriodMillis()),
                Long.toString(cost),
                Long.toString(now.toEpochMilli()),
                Long.toString(policy.bucketTtlMillis()));

        return redisTemplate.execute(tokenBucketScript, keys, args)
                // Flatten defensively: a multi-bulk reply may surface as one
                // emission or as several, depending on the driver's decoding.
                .reduce(new ArrayList<Long>(EXPECTED_REPLY_ARITY), (accumulator, chunk) -> {
                    accumulator.addAll(chunk);
                    return accumulator;
                })
                .map(reply -> toVerdict(reply, policy, bucketKey, now))
                .doOnNext(verdict -> {
                    recordLatency(policy, startedAt);
                    countDecision(policy, verdict.allowed() ? "allowed" : "denied");
                })
                .onErrorResume(error -> degrade(error, policy, fingerprint, now));
    }

    /**
     * Translates the raw Lua reply into a domain verdict.
     *
     * @param reply     {@code [allowed, remaining, retryAfterMillis, capacity]}
     * @param policy    policy applied
     * @param bucketKey bucket consulted
     * @param now       decision instant
     * @return verdict
     * @throws IllegalStateException when the reply arity is not the contracted one
     */
    private RateLimitVerdict toVerdict(List<Long> reply, RateLimitPolicy policy,
                                       String bucketKey, Instant now) {
        if (reply.size() < EXPECTED_REPLY_ARITY) {
            throw new IllegalStateException("Malformed token bucket reply for policy '"
                    + policy.name() + "': expected " + EXPECTED_REPLY_ARITY
                    + " elements but received " + reply.size());
        }

        boolean allowed = reply.get(0) == 1L;
        long remaining = Math.max(0L, reply.get(1));

        if (allowed) {
            return RateLimitVerdict.allow(policy, bucketKey, remaining, now);
        }
        Duration retryAfter = Duration.ofMillis(Math.max(0L, reply.get(2)));
        return RateLimitVerdict.deny(policy, bucketKey, remaining, retryAfter, now);
    }

    /**
     * Converts a backend failure into a verdict dictated by the fail-open flag.
     *
     * @param error       the backend failure
     * @param policy      policy applied
     * @param fingerprint request metadata, for the log line
     * @param now         decision instant
     * @return degraded verdict, never an error
     */
    private Mono<RateLimitVerdict> degrade(Throwable error, RateLimitPolicy policy,
                                           RequestFingerprint fingerprint, Instant now) {
        boolean failOpen = properties.getRateLimit().isFailOpen();
        countDecision(policy, failOpen ? "degraded-open" : "degraded-closed");

        log.error("Rate-limit backend unavailable [policy={}, identity={}, correlationId={}]. "
                        + "Applying fail-{} policy.",
                policy.name(), fingerprint.identity().asKeySegment(),
                fingerprint.correlationId(), failOpen ? "open" : "closed", error);

        return Mono.just(RateLimitVerdict.degraded(policy, failOpen, now));
    }

    /**
     * Builds the bucket key.
     *
     * <p>The policy name is part of the key on purpose: re-tuning a policy, or
     * moving a caller between tiers, must not let it inherit the allowance
     * accumulated under the previous one.</p>
     *
     * @param policy      policy applied
     * @param fingerprint request metadata
     * @return fully qualified Redis key
     */
    private String bucketKey(RateLimitPolicy policy, RequestFingerprint fingerprint) {
        return properties.getRateLimit().getKeyPrefix()
                + ':' + policy.name()
                + ':' + fingerprint.identity().asKeySegment();
    }

    private void countDecision(RateLimitPolicy policy, String outcome) {
        Counter.builder(DECISION_METRIC)
                .description("Token bucket admission decisions")
                .tag("policy", policy.name())
                .tag("outcome", outcome)
                .register(meterRegistry)
                .increment();
    }

    private void recordLatency(RateLimitPolicy policy, long startedAtNanos) {
        meterRegistry.timer(LATENCY_METRIC, "policy", policy.name())
                .record(Duration.ofNanos(System.nanoTime() - startedAtNanos));
    }
}
