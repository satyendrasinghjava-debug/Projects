/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Sorted-set implementation of {@link SlidingWindowCounter}.
 *
 * <p>Eviction, insertion, TTL refresh and measurement all happen inside one
 * atomic Lua invocation, so two concurrent replicas can never observe a window
 * mid-mutation and under-count a burst.</p>
 *
 * @author Satyendra Singh
 */
@Component
public class RedisSlidingWindowCounter implements SlidingWindowCounter {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final RedisScript<Long> slidingWindowScript;
    private final Clock clock;

    /**
     * @param redisTemplate       reactive Redis template
     * @param slidingWindowScript SHA-cached sliding-window program
     * @param clock               UTC clock supplying event scores
     */
    public RedisSlidingWindowCounter(ReactiveStringRedisTemplate redisTemplate,
                                     RedisScript<Long> slidingWindowScript,
                                     Clock clock) {
        this.redisTemplate = redisTemplate;
        this.slidingWindowScript = slidingWindowScript;
        this.clock = clock;
    }

    @Override
    public Mono<Long> observe(String windowKey, String member, Duration window, Duration ttl) {
        Instant now = Instant.now(clock);
        List<String> args = List.of(
                Long.toString(now.toEpochMilli()),
                Long.toString(window.toMillis()),
                member,
                Long.toString(ttl.toMillis()));

        return redisTemplate.execute(slidingWindowScript, List.of(windowKey), args)
                .next()
                .defaultIfEmpty(0L);
    }
}
