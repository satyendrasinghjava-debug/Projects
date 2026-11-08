/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.config;

import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.RateLimitPolicy;
import com.satyendra.sentinelguard.domain.ThreatLevel;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Externalised configuration for the whole engine, bound from the
 * {@code sentinelguard.*} namespace.
 *
 * <p>Mutable JavaBean style is used deliberately rather than constructor-bound
 * records: it keeps deeply nested maps and lists relaxed-bindable from
 * environment variables (the Kubernetes/Docker case) with no
 * {@code @DefaultValue} ceremony, and every value is copied into an immutable
 * {@link RateLimitPolicy} before it reaches the hot path.</p>
 *
 * @author Satyendra Singh
 */
@ConfigurationProperties(prefix = "sentinelguard")
public class SentinelGuardProperties {

    @NestedConfigurationProperty
    private final RateLimit rateLimit = new RateLimit();

    @NestedConfigurationProperty
    private final Fraud fraud = new Fraud();

    @NestedConfigurationProperty
    private final Identity identity = new Identity();

    @NestedConfigurationProperty
    private final Alerts alerts = new Alerts();

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public Fraud getFraud() {
        return fraud;
    }

    public Identity getIdentity() {
        return identity;
    }

    public Alerts getAlerts() {
        return alerts;
    }

    // =====================================================================
    // Rate limiting
    // =====================================================================

    /** Token-bucket configuration. */
    public static class RateLimit {

        /** Master switch; when false the filter becomes a pass-through. */
        private boolean enabled = true;

        /**
         * Behaviour when Redis cannot be reached. {@code true} favours
         * availability (admit traffic), {@code false} favours protection
         * (shed traffic). Payment-grade deployments usually want {@code false}.
         */
        private boolean failOpen = true;

        /** Namespace for every bucket key. */
        private String keyPrefix = "sentinelguard:rl";

        /** Paths that bypass limiting entirely (Ant-style patterns). */
        private List<String> excludedPaths = new ArrayList<>(List.of(
                "/actuator/**", "/favicon.ico"));

        /** Policy applied when no route or identity override matches. */
        @NestedConfigurationProperty
        private Policy defaultPolicy = new Policy();

        /** Named, reusable policies referenced by routes and identity overrides. */
        private Map<String, Policy> policies = new LinkedHashMap<>();

        /** Ordered path-pattern to policy-name bindings; first match wins. */
        private List<RouteRule> routes = new ArrayList<>();

        /** Per identity-provenance policy overrides, applied after routes. */
        private Map<IdentityType, String> identityPolicies = new EnumMap<>(IdentityType.class);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isFailOpen() {
            return failOpen;
        }

        public void setFailOpen(boolean failOpen) {
            this.failOpen = failOpen;
        }

        public String getKeyPrefix() {
            return keyPrefix;
        }

        public void setKeyPrefix(String keyPrefix) {
            this.keyPrefix = keyPrefix;
        }

        public List<String> getExcludedPaths() {
            return excludedPaths;
        }

        public void setExcludedPaths(List<String> excludedPaths) {
            this.excludedPaths = excludedPaths;
        }

        public Policy getDefaultPolicy() {
            return defaultPolicy;
        }

        public void setDefaultPolicy(Policy defaultPolicy) {
            this.defaultPolicy = defaultPolicy;
        }

        public Map<String, Policy> getPolicies() {
            return policies;
        }

        public void setPolicies(Map<String, Policy> policies) {
            this.policies = policies;
        }

        public List<RouteRule> getRoutes() {
            return routes;
        }

        public void setRoutes(List<RouteRule> routes) {
            this.routes = routes;
        }

        public Map<IdentityType, String> getIdentityPolicies() {
            return identityPolicies;
        }

        public void setIdentityPolicies(Map<IdentityType, String> identityPolicies) {
            this.identityPolicies = identityPolicies;
        }
    }

    /** Raw, bindable form of a token-bucket policy. */
    public static class Policy {

        /** Maximum burst, in tokens. */
        private long capacity = 100L;

        /** Tokens credited once per {@link #refillPeriod}. */
        private long refillTokens = 100L;

        /** Length of one refill interval. */
        private Duration refillPeriod = Duration.ofMinutes(1);

        /** Cost of a single request. */
        private long tokensPerRequest = 1L;

        /** Idle expiry of the bucket key, reclaiming memory for dormant callers. */
        private Duration bucketTtl = Duration.ofMinutes(10);

        public long getCapacity() {
            return capacity;
        }

        public void setCapacity(long capacity) {
            this.capacity = capacity;
        }

        public long getRefillTokens() {
            return refillTokens;
        }

        public void setRefillTokens(long refillTokens) {
            this.refillTokens = refillTokens;
        }

        public Duration getRefillPeriod() {
            return refillPeriod;
        }

        public void setRefillPeriod(Duration refillPeriod) {
            this.refillPeriod = refillPeriod;
        }

        public long getTokensPerRequest() {
            return tokensPerRequest;
        }

        public void setTokensPerRequest(long tokensPerRequest) {
            this.tokensPerRequest = tokensPerRequest;
        }

        public Duration getBucketTtl() {
            return bucketTtl;
        }

        public void setBucketTtl(Duration bucketTtl) {
            this.bucketTtl = bucketTtl;
        }

        /**
         * Freezes this mutable bean into the immutable domain policy used by the
         * hot path.
         *
         * @param name policy name to stamp
         * @return validated, immutable policy
         * @throws IllegalArgumentException when the configuration is unusable
         */
        public RateLimitPolicy toDomain(String name) {
            return new RateLimitPolicy(name, capacity, refillTokens, refillPeriod,
                    tokensPerRequest, bucketTtl);
        }
    }

    /** Binding of a path pattern to a named policy. */
    public static class RouteRule {

        /** Ant-style path pattern, e.g. {@code /api/v1/payments/**}. */
        private String pathPattern;

        /** Key into {@code sentinelguard.rate-limit.policies}. */
        private String policy;

        public String getPathPattern() {
            return pathPattern;
        }

        public void setPathPattern(String pathPattern) {
            this.pathPattern = pathPattern;
        }

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }
    }

    // =====================================================================
    // Fraud detection
    // =====================================================================

    /** Behavioural fraud-heuristic configuration. */
    public static class Fraud {

        /** Master switch for scoring and alert publication. */
        private boolean enabled = true;

        /** Namespace for sliding-window keys. */
        private String keyPrefix = "sentinelguard:fraud";

        /** Horizon over which behaviour is accumulated. */
        private Duration observationWindow = Duration.ofMinutes(1);

        /** Idle expiry of window keys; must exceed {@link #observationWindow}. */
        private Duration windowTtl = Duration.ofMinutes(5);

        /** Rejections inside the window that trigger {@code BURST_VELOCITY}. */
        private int burstRejectionThreshold = 5;

        /** Distinct paths inside the window that trigger {@code PATH_ENUMERATION}. */
        private int distinctPathThreshold = 15;

        /** Minimum band that is actually published to Kafka. */
        private ThreatLevel publishThreshold = ThreatLevel.MEDIUM;

        /** Case-insensitive regular expressions matched against the User-Agent. */
        private List<String> suspiciousUserAgentPatterns = new ArrayList<>(List.of(
                "(?i).*\\b(curl|wget|libwww-perl|httpie)\\b.*",
                "(?i).*(python-requests|aiohttp|okhttp|go-http-client|java/\\d).*",
                "(?i).*(scrapy|nikto|sqlmap|nmap|masscan|zgrab).*",
                "(?i).*(headlesschrome|phantomjs|puppeteer|playwright).*"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getKeyPrefix() {
            return keyPrefix;
        }

        public void setKeyPrefix(String keyPrefix) {
            this.keyPrefix = keyPrefix;
        }

        public Duration getObservationWindow() {
            return observationWindow;
        }

        public void setObservationWindow(Duration observationWindow) {
            this.observationWindow = observationWindow;
        }

        public Duration getWindowTtl() {
            return windowTtl;
        }

        public void setWindowTtl(Duration windowTtl) {
            this.windowTtl = windowTtl;
        }

        public int getBurstRejectionThreshold() {
            return burstRejectionThreshold;
        }

        public void setBurstRejectionThreshold(int burstRejectionThreshold) {
            this.burstRejectionThreshold = burstRejectionThreshold;
        }

        public int getDistinctPathThreshold() {
            return distinctPathThreshold;
        }

        public void setDistinctPathThreshold(int distinctPathThreshold) {
            this.distinctPathThreshold = distinctPathThreshold;
        }

        public ThreatLevel getPublishThreshold() {
            return publishThreshold;
        }

        public void setPublishThreshold(ThreatLevel publishThreshold) {
            this.publishThreshold = publishThreshold;
        }

        public List<String> getSuspiciousUserAgentPatterns() {
            return suspiciousUserAgentPatterns;
        }

        public void setSuspiciousUserAgentPatterns(List<String> suspiciousUserAgentPatterns) {
            this.suspiciousUserAgentPatterns = suspiciousUserAgentPatterns;
        }
    }

    // =====================================================================
    // Identity resolution
    // =====================================================================

    /** How a caller's identity is extracted from the exchange. */
    public static class Identity {

        /** Header carrying the API key. */
        private String apiKeyHeader = "X-API-Key";

        /** Header carrying the proxy chain. */
        private String forwardedHeader = "X-Forwarded-For";

        /** Header carrying (or receiving) the correlation id. */
        private String correlationHeader = "X-Correlation-Id";

        /**
         * Whether {@link #forwardedHeader} may be trusted. Only enable when the
         * service sits behind a proxy that strips client-supplied values,
         * otherwise a caller can rotate the header to mint fresh quotas.
         */
        private boolean trustForwardedHeaders = true;

        public String getApiKeyHeader() {
            return apiKeyHeader;
        }

        public void setApiKeyHeader(String apiKeyHeader) {
            this.apiKeyHeader = apiKeyHeader;
        }

        public String getForwardedHeader() {
            return forwardedHeader;
        }

        public void setForwardedHeader(String forwardedHeader) {
            this.forwardedHeader = forwardedHeader;
        }

        public String getCorrelationHeader() {
            return correlationHeader;
        }

        public void setCorrelationHeader(String correlationHeader) {
            this.correlationHeader = correlationHeader;
        }

        public boolean isTrustForwardedHeaders() {
            return trustForwardedHeaders;
        }

        public void setTrustForwardedHeaders(boolean trustForwardedHeaders) {
            this.trustForwardedHeaders = trustForwardedHeaders;
        }
    }

    // =====================================================================
    // Alert transport
    // =====================================================================

    /** Kafka side-channel configuration. */
    public static class Alerts {

        /** Destination topic. */
        private String topic = "fraud-alerts";

        /** Partition count used when the topic is provisioned by this service. */
        private int partitions = 6;

        /** Replication factor used when the topic is provisioned by this service. */
        private short replicationFactor = 1;

        /** Whether this service declares the topic on startup. */
        private boolean autoCreateTopic = true;

        /** Upper bound on a single publish attempt before it is abandoned. */
        private Duration sendTimeout = Duration.ofSeconds(5);

        public String getTopic() {
            return topic;
        }

        public void setTopic(String topic) {
            this.topic = topic;
        }

        public int getPartitions() {
            return partitions;
        }

        public void setPartitions(int partitions) {
            this.partitions = partitions;
        }

        public short getReplicationFactor() {
            return replicationFactor;
        }

        public void setReplicationFactor(short replicationFactor) {
            this.replicationFactor = replicationFactor;
        }

        public boolean isAutoCreateTopic() {
            return autoCreateTopic;
        }

        public void setAutoCreateTopic(boolean autoCreateTopic) {
            this.autoCreateTopic = autoCreateTopic;
        }

        public Duration getSendTimeout() {
            return sendTimeout;
        }

        public void setSendTimeout(Duration sendTimeout) {
            this.sendTimeout = sendTimeout;
        }
    }
}
