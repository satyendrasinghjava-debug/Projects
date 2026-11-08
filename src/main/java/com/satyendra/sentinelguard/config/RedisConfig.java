/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.List;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Declares the compiled Lua programs that give SentinelGuard its atomicity.
 *
 * <p>Spring Data Redis loads each script once via {@code SCRIPT LOAD} and then
 * dispatches with {@code EVALSHA}, falling back to {@code EVAL} on a
 * {@code NOSCRIPT} reply (for instance after a Redis restart or a failover to a
 * replica with a cold script cache). That means the full script body crosses
 * the wire at most once per node, while every request pays only the cost of a
 * 40-byte SHA-1 digest.</p>
 *
 * <p>The reactive {@code ReactiveStringRedisTemplate} itself is contributed by
 * Spring Boot's auto-configuration on top of a Lettuce connection factory, so
 * the Netty event loop is shared with the HTTP layer and no extra thread pool
 * is introduced.</p>
 *
 * @author Satyendra Singh
 */
@Configuration(proxyBeanMethods = false)
public class RedisConfig {

    /** Classpath location of the token-bucket program. */
    public static final String TOKEN_BUCKET_SCRIPT = "scripts/token_bucket.lua";

    /** Classpath location of the sliding-window program. */
    public static final String SLIDING_WINDOW_SCRIPT = "scripts/sliding_window.lua";

    /**
     * Token-bucket script returning
     * {@code [allowed, remainingTokens, retryAfterMillis, capacity]}.
     *
     * <p>Redis multi-bulk integer replies are surfaced by Lettuce as
     * {@link Long} values regardless of the configured value serializer, hence
     * the {@code List<Long>} result type.</p>
     *
     * @return lazily loaded, SHA-cached script handle
     */
    @Bean
    @SuppressWarnings("unchecked")
    public RedisScript<List<Long>> tokenBucketScript() {
        Class<?> resultType = List.class;
        return RedisScript.of(new ClassPathResource(TOKEN_BUCKET_SCRIPT),
                (Class<List<Long>>) resultType);
    }

    /**
     * Sliding-window script returning the distinct member cardinality inside
     * the observation window.
     *
     * @return lazily loaded, SHA-cached script handle
     */
    @Bean
    public RedisScript<Long> slidingWindowScript() {
        return RedisScript.of(new ClassPathResource(SLIDING_WINDOW_SCRIPT), Long.class);
    }
}
