/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.limiter;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link RateLimitPolicyResolver}, covering precedence,
 * exclusions and fail-fast validation of the configuration.
 *
 * @author Satyendra Singh
 */
@DisplayName("RateLimitPolicyResolver")
class RateLimitPolicyResolverTest {

    private SentinelGuardProperties properties;

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        SentinelGuardProperties.RateLimit config = properties.getRateLimit();

        config.getDefaultPolicy().setCapacity(100L);
        config.getDefaultPolicy().setRefillTokens(100L);
        config.getDefaultPolicy().setRefillPeriod(Duration.ofMinutes(1));

        config.getPolicies().put("payments-strict", policy(20L, Duration.ofMinutes(1)));
        config.getPolicies().put("anonymous-tight", policy(10L, Duration.ofMinutes(1)));

        config.setRoutes(List.of(
                route("/api/v1/transactions/**", "payments-strict"),
                route("/api/v1/sentinel/**", "anonymous-tight")));

        config.getIdentityPolicies().put(IdentityType.ANONYMOUS, "anonymous-tight");
        config.setExcludedPaths(List.of("/actuator/**", "/favicon.ico"));
    }

    @Test
    @DisplayName("a matching route wins over everything else")
    void routeTakesPrecedence() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        // Anonymous identity would normally be tightened, but the route is more specific.
        assertThat(resolver.resolve(fingerprint("/api/v1/transactions/abc", IdentityType.ANONYMOUS))
                .name()).isEqualTo("payments-strict");
    }

    @Test
    @DisplayName("routes are evaluated in declaration order")
    void firstMatchingRouteWins() {
        properties.getRateLimit().setRoutes(List.of(
                route("/api/**", "anonymous-tight"),
                route("/api/v1/transactions/**", "payments-strict")));

        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        assertThat(resolver.resolve(fingerprint("/api/v1/transactions/abc", IdentityType.API_KEY))
                .name()).isEqualTo("anonymous-tight");
    }

    @Test
    @DisplayName("an identity override applies when no route matches")
    void identityOverrideApplies() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        assertThat(resolver.resolve(fingerprint("/public/ping", IdentityType.ANONYMOUS)).name())
                .isEqualTo("anonymous-tight");
    }

    @Test
    @DisplayName("falls back to the default policy")
    void fallsBackToDefault() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        assertThat(resolver.resolve(fingerprint("/public/ping", IdentityType.API_KEY)).name())
                .isEqualTo("default");
        assertThat(resolver.defaultPolicy().capacity()).isEqualTo(100L);
    }

    @Test
    @DisplayName("exclusion patterns are honoured")
    void honoursExclusions() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        assertThat(resolver.isExcluded("/actuator/health")).isTrue();
        assertThat(resolver.isExcluded("/favicon.ico")).isTrue();
        assertThat(resolver.isExcluded("/api/v1/transactions")).isFalse();
    }

    @Test
    @DisplayName("named lookup resolves declared policies and the default")
    void namedLookup() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        assertThat(resolver.byName("payments-strict").capacity()).isEqualTo(20L);
        assertThat(resolver.byName("default").capacity()).isEqualTo(100L);
    }

    @Test
    @DisplayName("reports the sustained rate implied by a policy")
    void exposesSustainedRate() {
        RateLimitPolicyResolver resolver = new RateLimitPolicyResolver(properties);

        // 20 tokens per 60s at 1 token per request.
        assertThat(resolver.byName("payments-strict").sustainedRatePerSecond())
                .isCloseTo(0.3333d, org.assertj.core.data.Offset.offset(0.0001d));
    }

    // =====================================================================
    // Fail-fast configuration validation
    // =====================================================================

    @Test
    @DisplayName("a route referencing an undeclared policy fails the context at startup")
    void unknownRoutePolicyFailsFast() {
        properties.getRateLimit().setRoutes(List.of(route("/api/**", "does-not-exist")));

        assertThatThrownBy(() -> new RateLimitPolicyResolver(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown rate-limit policy 'does-not-exist'");
    }

    @Test
    @DisplayName("an identity override referencing an undeclared policy fails fast")
    void unknownIdentityPolicyFailsFast() {
        properties.getRateLimit().setRoutes(List.of());
        properties.getRateLimit().getIdentityPolicies().put(IdentityType.API_KEY, "nope");

        assertThatThrownBy(() -> new RateLimitPolicyResolver(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown rate-limit policy 'nope'");
    }

    @Test
    @DisplayName("a route without a path pattern fails fast")
    void missingPathPatternFailsFast() {
        properties.getRateLimit().setRoutes(List.of(route(null, "payments-strict")));

        assertThatThrownBy(() -> new RateLimitPolicyResolver(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("path-pattern");
    }

    @Test
    @DisplayName("a route without a policy name fails fast")
    void missingPolicyNameFailsFast() {
        properties.getRateLimit().setRoutes(List.of(route("/api/**", "  ")));

        assertThatThrownBy(() -> new RateLimitPolicyResolver(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing required configuration value");
    }

    @Test
    @DisplayName("a policy whose cost exceeds its capacity fails fast")
    void impossiblePolicyFailsFast() {
        SentinelGuardProperties.Policy broken = policy(5L, Duration.ofMinutes(1));
        broken.setTokensPerRequest(10L);
        properties.getRateLimit().getPolicies().put("broken", broken);
        properties.getRateLimit().setRoutes(List.of());

        assertThatThrownBy(() -> new RateLimitPolicyResolver(properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds capacity");
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static SentinelGuardProperties.Policy policy(long capacity, Duration period) {
        SentinelGuardProperties.Policy policy = new SentinelGuardProperties.Policy();
        policy.setCapacity(capacity);
        policy.setRefillTokens(capacity);
        policy.setRefillPeriod(period);
        policy.setTokensPerRequest(1L);
        policy.setBucketTtl(Duration.ofMinutes(10));
        return policy;
    }

    private static SentinelGuardProperties.RouteRule route(String pattern, String policyName) {
        SentinelGuardProperties.RouteRule rule = new SentinelGuardProperties.RouteRule();
        rule.setPathPattern(pattern);
        rule.setPolicy(policyName);
        return rule;
    }

    private static RequestFingerprint fingerprint(String path, IdentityType type) {
        return new RequestFingerprint("corr", new ClientIdentity("value", type), "198.51.100.4",
                "GET", path, "JUnit", Instant.parse("2026-02-01T10:15:30Z"));
    }
}
