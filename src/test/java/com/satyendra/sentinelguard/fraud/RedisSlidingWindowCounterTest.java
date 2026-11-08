/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link RedisSlidingWindowCounter}.
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RedisSlidingWindowCounter")
@SuppressWarnings({"unchecked", "rawtypes"})
class RedisSlidingWindowCounterTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-09T08:00:00Z");

    @Mock
    private ReactiveStringRedisTemplate redisTemplate;

    @Mock
    private RedisScript<Long> slidingWindowScript;

    private RedisSlidingWindowCounter counter;

    @BeforeEach
    void setUp() {
        counter = new RedisSlidingWindowCounter(redisTemplate, slidingWindowScript,
                Clock.fixed(FIXED_NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("returns the cardinality reported by Redis")
    void returnsCardinality() {
        doReturn(Flux.just(7L))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

        StepVerifier.create(counter.observe("win:key", "member-1",
                        Duration.ofMinutes(1), Duration.ofMinutes(5)))
                .expectNext(7L)
                .verifyComplete();
    }

    @Test
    @DisplayName("marshals now, window, member and ttl in the contracted order")
    void marshalsArguments() {
        doReturn(Flux.just(1L))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<String>> args = ArgumentCaptor.forClass(List.class);

        counter.observe("win:key", "member-1", Duration.ofMinutes(1), Duration.ofMinutes(5))
                .block(Duration.ofSeconds(1));

        verify(redisTemplate).execute(any(RedisScript.class), keys.capture(), args.capture());

        assertThat(keys.getValue()).containsExactly("win:key");
        assertThat(args.getValue()).containsExactly(
                Long.toString(FIXED_NOW.toEpochMilli()), "60000", "member-1", "300000");
    }

    @Test
    @DisplayName("an empty reply degrades to zero rather than hanging the evaluation")
    void emptyReplyBecomesZero() {
        doReturn(Flux.empty())
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

        StepVerifier.create(counter.observe("win:key", "member-1",
                        Duration.ofMinutes(1), Duration.ofMinutes(5)))
                .expectNext(0L)
                .verifyComplete();
    }

    @Test
    @DisplayName("propagates backend errors so the caller can decide")
    void propagatesErrors() {
        doReturn(Flux.error(new IllegalStateException("redis down")))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

        StepVerifier.create(counter.observe("win:key", "member-1",
                        Duration.ofMinutes(1), Duration.ofMinutes(5)))
                .expectErrorMessage("redis down")
                .verify();
    }
}
