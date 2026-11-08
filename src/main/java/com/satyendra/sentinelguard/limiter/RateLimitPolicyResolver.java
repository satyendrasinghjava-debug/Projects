/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.limiter;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.RequestFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Decides which {@link RateLimitPolicy} governs a request.
 *
 * <p>All configuration is validated and frozen into immutable structures in the
 * constructor, so a typo in {@code application.yml} fails the context at
 * startup instead of surfacing as a production 500. The hot path then performs
 * nothing but pattern matching and map lookups.</p>
 *
 * <h3>Precedence</h3>
 * <ol>
 *   <li>First matching route pattern (declaration order is significant).</li>
 *   <li>Override registered for the caller's {@link IdentityType}.</li>
 *   <li>The default policy.</li>
 * </ol>
 *
 * @author Satyendra Singh
 */
@Component
public class RateLimitPolicyResolver {

    private static final Logger log = LoggerFactory.getLogger(RateLimitPolicyResolver.class);

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final RateLimitPolicy defaultPolicy;
    private final Map<String, RateLimitPolicy> namedPolicies;
    private final List<CompiledRoute> routes;
    private final Map<IdentityType, RateLimitPolicy> identityOverrides;
    private final List<String> excludedPaths;

    /**
     * @param properties bound engine configuration
     * @throws IllegalStateException when a route or override references an
     *                               undeclared policy name
     */
    public RateLimitPolicyResolver(SentinelGuardProperties properties) {
        SentinelGuardProperties.RateLimit config = properties.getRateLimit();

        this.defaultPolicy = config.getDefaultPolicy().toDomain("default");
        this.excludedPaths = List.copyOf(config.getExcludedPaths());

        Map<String, RateLimitPolicy> resolved = new LinkedHashMap<>();
        config.getPolicies().forEach((name, policy) -> resolved.put(name, policy.toDomain(name)));
        resolved.putIfAbsent(defaultPolicy.name(), defaultPolicy);
        this.namedPolicies = Map.copyOf(resolved);

        List<CompiledRoute> compiled = new ArrayList<>();
        for (SentinelGuardProperties.RouteRule rule : config.getRoutes()) {
            compiled.add(new CompiledRoute(
                    require(rule.getPathPattern(), "sentinelguard.rate-limit.routes[].path-pattern"),
                    lookup(rule.getPolicy(), "route " + rule.getPathPattern())));
        }
        this.routes = List.copyOf(compiled);

        Map<IdentityType, RateLimitPolicy> overrides = new EnumMap<>(IdentityType.class);
        config.getIdentityPolicies().forEach((type, policyName) ->
                overrides.put(type, lookup(policyName, "identity override " + type)));
        this.identityOverrides = Map.copyOf(overrides);

        log.info("SentinelGuard policy table ready: default={} ({} req/s sustained, burst {}), "
                        + "namedPolicies={}, routes={}, identityOverrides={}, excludedPaths={}",
                defaultPolicy.name(), String.format("%.2f", defaultPolicy.sustainedRatePerSecond()),
                defaultPolicy.capacity(), namedPolicies.keySet(), routes.size(),
                identityOverrides.keySet(), excludedPaths);
    }

    /**
     * @param fingerprint request metadata
     * @return the governing policy; never {@code null}
     */
    public RateLimitPolicy resolve(RequestFingerprint fingerprint) {
        for (CompiledRoute route : routes) {
            if (pathMatcher.match(route.pattern(), fingerprint.path())) {
                return route.policy();
            }
        }
        RateLimitPolicy override = identityOverrides.get(fingerprint.identity().type());
        return override != null ? override : defaultPolicy;
    }

    /**
     * @param path request path
     * @return {@code true} when the path must bypass limiting entirely
     */
    public boolean isExcluded(String path) {
        for (String pattern : excludedPaths) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    /** @return the fallback policy */
    public RateLimitPolicy defaultPolicy() {
        return defaultPolicy;
    }

    /**
     * @param name declared policy name
     * @return the named policy
     * @throws IllegalStateException when undeclared
     */
    public RateLimitPolicy byName(String name) {
        return lookup(name, "lookup");
    }

    private RateLimitPolicy lookup(String name, String origin) {
        String policyName = require(name, origin + " -> policy");
        if (namedPolicies.containsKey(policyName)) {
            return namedPolicies.get(policyName);
        }
        if (defaultPolicy.name().equals(policyName)) {
            return defaultPolicy;
        }
        throw new IllegalStateException("Unknown rate-limit policy '" + policyName
                + "' referenced by " + origin
                + ". Declare it under sentinelguard.rate-limit.policies.");
    }

    private static String require(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing required configuration value: " + what);
        }
        return value;
    }

    /**
     * Pre-resolved route binding.
     *
     * @param pattern Ant-style path pattern
     * @param policy  immutable policy to apply
     */
    private record CompiledRoute(String pattern, RateLimitPolicy policy) {
    }
}
