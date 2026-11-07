/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.limiter;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RateLimitVerdict;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.RedisConnectionFailureException;
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
 * Unit tests for {@link RedisTokenBucketRateLimiter}.
 *
 * <p>Redis is mocked on purpose here: this suite pins the limiter's
 * <em>contract</em> (argument marshalling, reply interpretation, degradation
 * behaviour, metrics) without a container, and runs in milliseconds. The Lua
 * program's own arithmetic is verified against a live Redis in
 * {@code SentinelGuardEndToEndIT}.</p>
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RedisTokenBucketRateLimiter")
@SuppressWarnings({"unchecked", "rawtypes"})
class RedisTokenBucketRateLimiterTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-02-01T10:15:30Z");

    @Mock
    private ReactiveStringRedisTemplate redisTemplate;

    @Mock
    private RedisScript<List<Long>> tokenBucketScript;

    private SentinelGuardProperties properties;
    private MeterRegistry meterRegistry;
    private RedisTokenBucketRateLimiter limiter;

    private final RateLimitPolicy policy = new RateLimitPolicy(
            "payments-strict", 20L, 20L, Duration.ofMinutes(1), 1L, Duration.ofMinutes(10));

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        properties.getRateLimit().setKeyPrefix("sentinelguard:rl");
        meterRegistry = new SimpleMeterRegistry();
        limiter = new RedisTokenBucketRateLimiter(redisTemplate, tokenBucketScript, properties,
                meterRegistry, Clock.fixed(FIXED_NOW, ZoneOffset.UTC));
    }

    // =====================================================================
    // Happy paths
    // =====================================================================

    @Test
    @DisplayName("admits the request and reports the remaining allowance")
    void admitsWhenTokensAvailable() {
        stubReply(1L, 19L, 0L, 20L);

        StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                .assertNext(verdict -> {
                    assertThat(verdict.allowed()).isTrue();
                    assertThat(verdict.remaining()).isEqualTo(19L);
                    assertThat(verdict.limit()).isEqualTo(20L);
                    assertThat(verdict.retryAfter()).isZero();
                    assertThat(verdict.degraded()).isFalse();
                    assertThat(verdict.policyName()).isEqualTo("payments-strict");
                    assertThat(verdict.resetAt()).isEqualTo(FIXED_NOW.plus(Duration.ofMinutes(1)));
                })
                .verifyComplete();

        assertThat(decisionCount("allowed")).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("rejects the request and surfaces the exact retry hint")
    void rejectsWhenBucketExhausted() {
        stubReply(0L, 0L, 2_500L, 20L);

        StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                .assertNext(verdict -> {
                    assertThat(verdict.allowed()).isFalse();
                    assertThat(verdict.remaining()).isZero();
                    assertThat(verdict.retryAfter()).isEqualTo(Duration.ofMillis(2_500L));
                    // 2.5s must round up: a client obeying 2s would be rejected again.
                    assertThat(verdict.retryAfterSeconds()).isEqualTo(3L);
                    assertThat(verdict.resetAt()).isEqualTo(FIXED_NOW.plusMillis(2_500L));
                })
                .verifyComplete();

        assertThat(decisionCount("denied")).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("marshals the policy, the cost and the clock into the script arguments")
    void marshalsScriptArguments() {
        stubReply(1L, 19L, 0L, 20L);
        ArgumentCaptor<List<String>> keys = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<String>> args = ArgumentCaptor.forClass(List.class);

        limiter.tryConsume(fingerprint(), policy).block(Duration.ofSeconds(1));

        verify(redisTemplate).execute(any(RedisScript.class), keys.capture(), args.capture());

        assertThat(keys.getValue())
                .containsExactly("sentinelguard:rl:payments-strict:ak:client-digest");
        assertThat(args.getValue()).containsExactly(
                "20",                                        // capacity
                "20",                                        // refill tokens
                "60000",                                     // refill period millis
                "1",                                         // tokens charged
                Long.toString(FIXED_NOW.toEpochMilli()),     // deterministic clock
                "600000");                                   // bucket ttl millis
    }

    @Test
    @DisplayName("peek charges zero tokens so the snapshot is non-mutating")
    void peekChargesNothing() {
        stubReply(1L, 20L, 0L, 20L);
        ArgumentCaptor<List<String>> args = ArgumentCaptor.forClass(List.class);

        StepVerifier.create(limiter.peek(fingerprint(), policy))
                .assertNext(verdict -> assertThat(verdict.remaining()).isEqualTo(20L))
                .verifyComplete();

        verify(redisTemplate).execute(any(RedisScript.class), anyList(), args.capture());
        assertThat(args.getValue().get(3)).isEqualTo("0");
    }

    @Test
    @DisplayName("flattens a multi-emission reply into one verdict")
    void flattensChunkedReply() {
        doReturn(Flux.just(List.of(1L, 7L), List.of(0L, 20L)))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

        StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                .assertNext(verdict -> {
                    assertThat(verdict.allowed()).isTrue();
                    assertThat(verdict.remaining()).isEqualTo(7L);
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("clamps a negative remaining or retry value reported by the backend")
    void clampsNegativeValues() {
        stubReply(0L, -5L, -10L, 20L);

        StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                .assertNext(verdict -> {
                    assertThat(verdict.remaining()).isZero();
                    assertThat(verdict.retryAfter()).isZero();
                    assertThat(verdict.retryAfterSeconds()).isZero();
                })
                .verifyComplete();
    }

    // =====================================================================
    // Degradation
    // =====================================================================

    @Nested
    @DisplayName("when the quota backend is unavailable")
    class Degradation {

        @Test
        @DisplayName("fail-open admits the request and flags the verdict as degraded")
        void failsOpen() {
            properties.getRateLimit().setFailOpen(true);
            stubError();

            StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                    .assertNext(verdict -> {
                        assertThat(verdict.allowed()).isTrue();
                        assertThat(verdict.degraded()).isTrue();
                        assertThat(verdict.remaining()).isEqualTo(policy.capacity());
                        assertThat(verdict.bucketKey()).isEqualTo("unavailable");
                    })
                    .verifyComplete();

            assertThat(decisionCount("degraded-open")).isEqualTo(1.0d);
        }

        @Test
        @DisplayName("fail-closed sheds the request with a full-period retry hint")
        void failsClosed() {
            properties.getRateLimit().setFailOpen(false);
            stubError();

            StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                    .assertNext(verdict -> {
                        assertThat(verdict.allowed()).isFalse();
                        assertThat(verdict.degraded()).isTrue();
                        assertThat(verdict.remaining()).isZero();
                        assertThat(verdict.retryAfterSeconds()).isEqualTo(60L);
                    })
                    .verifyComplete();

            assertThat(decisionCount("degraded-closed")).isEqualTo(1.0d);
        }

        @Test
        @DisplayName("a malformed reply is treated as a backend fault, never as an allow")
        void malformedReplyDegrades() {
            properties.getRateLimit().setFailOpen(false);
            doReturn(Flux.just(List.of(1L, 2L)))
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

            StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                    .assertNext(verdict -> {
                        assertThat(verdict.allowed()).isFalse();
                        assertThat(verdict.degraded()).isTrue();
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("an empty reply stream is treated as a backend fault")
        void emptyReplyDegrades() {
            properties.getRateLimit().setFailOpen(true);
            doReturn(Flux.empty())
                    .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());

            StepVerifier.create(limiter.tryConsume(fingerprint(), policy))
                    .assertNext(verdict -> assertThat(verdict.degraded()).isTrue())
                    .verifyComplete();
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private void stubReply(Long... reply) {
        doReturn(Flux.just(List.of(reply)))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());
    }

    private void stubError() {
        doReturn(Flux.error(new RedisConnectionFailureException("redis is down")))
                .when(redisTemplate).execute(any(RedisScript.class), anyList(), anyList());
    }

    private double decisionCount(String outcome) {
        return meterRegistry.get("sentinelguard.ratelimit.decisions")
                .tag("policy", policy.name())
                .tag("outcome", outcome)
                .counter()
                .count();
    }

    private static RequestFingerprint fingerprint() {
        return new RequestFingerprint(
                "corr-1",
                new ClientIdentity("client-digest", IdentityType.API_KEY),
                "203.0.113.7",
                "POST",
                "/api/v1/transactions",
                "Mozilla/5.0",
                FIXED_NOW);
    }

    /** Guards against an accidental signature change on the verdict factory. */
    @Test
    @DisplayName("degraded verdict factory is self-consistent")
    void degradedFactoryContract() {
        RateLimitVerdict open = RateLimitVerdict.degraded(policy, true, FIXED_NOW);
        RateLimitVerdict closed = RateLimitVerdict.degraded(policy, false, FIXED_NOW);

        assertThat(open.allowed()).isTrue();
        assertThat(open.retryAfter()).isZero();
        assertThat(closed.allowed()).isFalse();
        assertThat(closed.retryAfter()).isEqualTo(Duration.ofMinutes(1));
    }
}
