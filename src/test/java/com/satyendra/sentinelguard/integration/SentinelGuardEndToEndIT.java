/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.satyendra.sentinelguard.web.RateLimitWebFilter;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * End-to-end verification of the whole engine against <em>live</em>
 * infrastructure: a real Redis and a real Kafka broker started by
 * Testcontainers, the real Netty server, the real Lua scripts and the real
 * producer.
 *
 * <p>This is the suite that proves the things a mocked unit test cannot:</p>
 * <ul>
 *   <li>the Lua program's refill and admission arithmetic actually behaves as
 *       a token bucket when executed by Redis;</li>
 *   <li>{@code EVALSHA} dispatch, key namespacing and {@code PEXPIRE}
 *       housekeeping work against a genuine server;</li>
 *   <li>buckets are isolated per identity, so one noisy tenant cannot consume
 *       another's quota;</li>
 *   <li>an alert really is serialised, partitioned and durably accepted by a
 *       broker, and is consumable by a non-Java client (plain JSON, no
 *       {@code __TypeId__} header).</li>
 * </ul>
 *
 * <p>Requires a running Docker daemon. Executed by the Failsafe plugin during
 * {@code mvn verify}; skip it with {@code -DskipITs}.</p>
 *
 * @author Satyendra Singh
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@DisplayName("SentinelGuard end-to-end (live Redis + Kafka)")
class SentinelGuardEndToEndIT {

    private static final String ALERT_TOPIC = "fraud-alerts";

    /** Bucket capacity forced down so the limit can be reached in four calls. */
    private static final int CAPACITY = 3;

    @Container
    @SuppressWarnings("resource")
    static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
                    .withExposedPorts(6379)
                    .waitingFor(Wait.forListeningPort());

    @Container
    @SuppressWarnings({"resource", "deprecation"})
    static final KafkaContainer KAFKA =
            new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.6.1"));

    /**
     * Points the application at the ephemeral container ports and tightens the
     * policy so the test stays fast and deterministic.
     *
     * @param registry Spring's dynamic property registry
     */
    @DynamicPropertySource
    static void registerContainerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);

        registry.add("sentinelguard.rate-limit.policies.payments-strict.capacity", () -> CAPACITY);
        registry.add("sentinelguard.rate-limit.policies.payments-strict.refill-tokens", () -> CAPACITY);
        registry.add("sentinelguard.rate-limit.policies.payments-strict.refill-period", () -> "60s");
        registry.add("sentinelguard.rate-limit.policies.payments-strict.bucket-ttl", () -> "120s");

        // One rejection is enough to raise BURST_VELOCITY in this test.
        registry.add("sentinelguard.fraud.burst-rejection-threshold", () -> 1);
        // Single partition keeps alert consumption deterministic.
        registry.add("sentinelguard.alerts.partitions", () -> 1);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        webTestClient = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .responseTimeout(Duration.ofSeconds(20))
                .build();

        // Clear every bucket and window so each test starts from a cold quota.
        redisTemplate.keys("sentinelguard:*")
                .flatMap(redisTemplate::delete)
                .then()
                .block(Duration.ofSeconds(10));
    }

    // =====================================================================
    // Rate limiting
    // =====================================================================

    @Test
    @DisplayName("admits exactly the bucket capacity, then sheds with a precise 429")
    void enforcesQuotaEndToEnd() {
        String apiKey = "it-key-" + UUID.randomUUID();

        for (int attempt = 1; attempt <= CAPACITY; attempt++) {
            int expectedRemaining = CAPACITY - attempt;
            submitTransaction(apiKey)
                    .expectStatus().isCreated()
                    .expectHeader().valueEquals(RateLimitWebFilter.HEADER_LIMIT, String.valueOf(CAPACITY))
                    .expectHeader().valueEquals(RateLimitWebFilter.HEADER_REMAINING,
                            String.valueOf(expectedRemaining))
                    .expectHeader().valueEquals(RateLimitWebFilter.HEADER_POLICY, "payments-strict")
                    .expectHeader().exists(RateLimitWebFilter.HEADER_RESET)
                    .expectBody()
                    .jsonPath("$.status").isEqualTo("ACCEPTED")
                    .jsonPath("$.transactionId").exists()
                    .jsonPath("$.correlationId").exists();
        }

        submitTransaction(apiKey)
                .expectStatus().isEqualTo(429)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectHeader().exists(HttpHeaders.RETRY_AFTER)
                .expectHeader().valueEquals(RateLimitWebFilter.HEADER_REMAINING, "0")
                .expectBody()
                .jsonPath("$.status").isEqualTo(429)
                .jsonPath("$.title").isEqualTo("Too Many Requests")
                .jsonPath("$.policy").isEqualTo("payments-strict")
                .jsonPath("$.retryAfter").isEqualTo(60)
                .jsonPath("$.correlationId").exists();
    }

    @Test
    @DisplayName("buckets are isolated per identity, so tenants cannot starve each other")
    void bucketsAreIsolatedPerIdentity() {
        String noisyTenant = "it-noisy-" + UUID.randomUUID();
        String quietTenant = "it-quiet-" + UUID.randomUUID();

        for (int attempt = 0; attempt < CAPACITY; attempt++) {
            submitTransaction(noisyTenant).expectStatus().isCreated();
        }
        submitTransaction(noisyTenant).expectStatus().isEqualTo(429);

        // The second tenant must still see a completely untouched allowance.
        submitTransaction(quietTenant)
                .expectStatus().isCreated()
                .expectHeader().valueEquals(RateLimitWebFilter.HEADER_REMAINING,
                        String.valueOf(CAPACITY - 1));
    }

    @Test
    @DisplayName("the bucket key is created with a TTL so dormant callers self-evict")
    void bucketKeysExpire() {
        String apiKey = "it-ttl-" + UUID.randomUUID();
        submitTransaction(apiKey).expectStatus().isCreated();

        List<String> keys = redisTemplate.keys("sentinelguard:rl:payments-strict:*")
                .collectList()
                .block(Duration.ofSeconds(10));

        assertThat(keys).isNotNull().isNotEmpty();

        Duration ttl = redisTemplate.getExpire(keys.get(0)).block(Duration.ofSeconds(10));
        assertThat(ttl).isNotNull();
        assertThat(ttl).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(120));
    }

    @Test
    @DisplayName("the quota endpoint reports the allowance without charging a token")
    void quotaEndpointDoesNotCharge() {
        String apiKey = "it-quota-" + UUID.randomUUID();

        for (int probe = 0; probe < 3; probe++) {
            webTestClient.get()
                    .uri("/api/v1/sentinel/quota")
                    .header("X-API-Key", apiKey)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    // The standard policy governs this path; repeated probes must
                    // not move the figure.
                    .jsonPath("$.policy").isEqualTo("standard")
                    .jsonPath("$.remaining").isEqualTo(100)
                    .jsonPath("$.identityType").isEqualTo("API_KEY")
                    .jsonPath("$.degraded").isEqualTo(false);
        }
    }

    @Test
    @DisplayName("health probes are never rate limited")
    void actuatorIsExcluded() {
        for (int attempt = 0; attempt < CAPACITY + 3; attempt++) {
            webTestClient.get()
                    .uri("/actuator/health")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().doesNotExist(RateLimitWebFilter.HEADER_LIMIT);
        }
    }

    @Test
    @DisplayName("validation failures are reported per field")
    void validationIsEnforced() {
        webTestClient.post()
                .uri("/api/v1/transactions")
                .header("X-API-Key", "it-valid-" + UUID.randomUUID())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("reference", "", "amount", "0.00",
                        "currency", "usd", "beneficiary", "ACC-1"))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.status").isEqualTo(400)
                .jsonPath("$.fieldViolations.currency").exists()
                .jsonPath("$.fieldViolations.amount").exists()
                .jsonPath("$.fieldViolations.reference").exists();
    }

    // =====================================================================
    // Fraud detection
    // =====================================================================

    @Test
    @DisplayName("a shed request produces a consumable fraud alert on the Kafka topic")
    void publishesFraudAlertToKafka() {
        String apiKey = "it-fraud-" + UUID.randomUUID();

        for (int attempt = 0; attempt < CAPACITY; attempt++) {
            submitTransaction(apiKey).expectStatus().isCreated();
        }
        // This rejection is what trips RATE_LIMIT_BREACH + BURST_VELOCITY.
        submitTransaction(apiKey).expectStatus().isEqualTo(429);

        List<ConsumerRecord<String, String>> alerts =
                consumeAlerts(identityOf(apiKey), 1, Duration.ofSeconds(30));

        assertThat(alerts).as("expected at least one fraud alert on '%s'", ALERT_TOPIC)
                .isNotEmpty();

        ConsumerRecord<String, String> record = alerts.get(alerts.size() - 1);
        JsonNode alert = readJson(record.value());

        assertThat(alert.get("alertId").asText()).isNotBlank();
        assertThat(alert.get("correlationId").asText()).isNotBlank();
        assertThat(alert.get("identityType").asText()).isEqualTo("API_KEY");
        assertThat(alert.get("path").asText()).isEqualTo("/api/v1/transactions");
        assertThat(alert.get("httpMethod").asText()).isEqualTo("POST");
        assertThat(alert.get("policyName").asText()).isEqualTo("payments-strict");
        assertThat(alert.get("riskScore").asInt()).isGreaterThanOrEqualTo(55);
        assertThat(alert.get("threatLevel").asText()).isIn("HIGH", "CRITICAL");

        List<String> signals = new ArrayList<>();
        alert.get("signals").forEach(node -> signals.add(node.asText()));
        assertThat(signals).contains("RATE_LIMIT_BREACH", "BURST_VELOCITY");

        // The record is keyed by identity so consumers get causal ordering...
        assertThat(record.key()).isEqualTo(alert.get("clientId").asText());
        // ...and carries routing headers for cheap, body-free filtering.
        assertThat(header(record, "X-Sentinel-Threat-Level"))
                .isEqualTo(alert.get("threatLevel").asText());
        assertThat(header(record, "X-Sentinel-Risk-Score"))
                .isEqualTo(String.valueOf(alert.get("riskScore").asInt()));

        // The credential must never leave the process in clear text.
        assertThat(record.value()).doesNotContain(apiKey);
        // ISO-8601, not an epoch array, so non-JVM consumers can parse it.
        assertThat(alert.get("detectedAt").asText()).contains("T");
    }

    @Test
    @DisplayName("clean traffic produces no alerts at all")
    void cleanTrafficIsSilent() {
        String apiKey = "it-clean-" + UUID.randomUUID();

        submitTransaction(apiKey).expectStatus().isCreated();

        // A single admitted request with an API key trips no heuristic, so this
        // identity must contribute nothing to the topic.
        assertThat(consumeAlerts(identityOf(apiKey), 1, Duration.ofSeconds(8))).isEmpty();
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private WebTestClient.ResponseSpec submitTransaction(String apiKey) {
        return webTestClient.post()
                .uri("/api/v1/transactions")
                .header("X-API-Key", apiKey)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of(
                        "reference", "it-ref-" + UUID.randomUUID(),
                        "amount", "125.50",
                        "currency", "USD",
                        "beneficiary", "ACC-998877"))
                .exchange();
    }

    /**
     * Drains the alert topic until the expected number of records has been seen
     * or the timeout elapses.
     *
     * <p>Partitions are assigned explicitly rather than subscribed, so there is
     * no consumer-group rebalance to wait on and the read is deterministic.</p>
     *
     * @param clientId        identity whose alerts are of interest; every test in
     *                         this class shares one topic, so filtering by the
     *                         record key is what keeps the assertions independent
     * @param expectedAtLeast number of records to wait for
     * @param timeout         maximum time to wait
     * @return the matching records observed, oldest first
     */
    private List<ConsumerRecord<String, String>> consumeAlerts(String clientId,
                                                               int expectedAtLeast,
                                                               Duration timeout) {
        List<ConsumerRecord<String, String>> collected = new ArrayList<>();
        TopicPartition partition = new TopicPartition(ALERT_TOPIC, 0);
        long deadline = System.nanoTime() + timeout.toNanos();

        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerConfig())) {
            consumer.assign(List.of(partition));
            consumer.seekToBeginning(List.of(partition));

            while (System.nanoTime() < deadline && collected.size() < expectedAtLeast) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records.records(partition)) {
                    if (clientId.equals(record.key())) {
                        collected.add(record);
                    }
                }
            }
        }
        return collected;
    }

    private Map<String, Object> consumerConfig() {
        return Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers(),
                ConsumerConfig.GROUP_ID_CONFIG, "sentinelguard-it-" + UUID.randomUUID(),
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, Boolean.FALSE);
    }

    /**
     * Reproduces {@code ClientIdentityResolver}'s credential digest, which is
     * also the Kafka record key. Asserting against it proves the raw API key
     * never leaves the process.
     *
     * @param apiKey the API key sent by the test
     * @return the identity value the engine will have derived
     */
    private static String identityOf(String apiKey) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(apiKey.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash).substring(0, 32);
        } catch (java.security.NoSuchAlgorithmException cause) {
            throw new AssertionError(cause);
        }
    }

    private static String header(ConsumerRecord<String, String> record, String name) {
        return new String(record.headers().lastHeader(name).value(), StandardCharsets.UTF_8);
    }

    private JsonNode readJson(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (Exception cause) {
            throw new AssertionError("Alert payload was not valid JSON: " + payload, cause);
        }
    }
}
