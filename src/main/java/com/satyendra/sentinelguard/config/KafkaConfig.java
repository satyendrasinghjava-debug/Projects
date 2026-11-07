/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.satyendra.sentinelguard.domain.FraudAlert;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Producer-side Kafka wiring for the {@code fraud-alerts} side channel.
 *
 * <h3>Why these settings</h3>
 * <ul>
 *   <li>{@code acks=all} + {@code enable.idempotence=true} + bounded retries:
 *       an alert survives a broker failover without being duplicated or
 *       reordered. Losing a fraud alert is a security event, not a nuisance.</li>
 *   <li>{@code max.block.ms} is kept small and finite. {@code KafkaProducer#send}
 *       blocks the calling thread while metadata is unknown or the accumulator
 *       is full, and an unbounded block on a Netty event loop would stall
 *       unrelated traffic. The publisher additionally offloads to
 *       {@code boundedElastic()}, so the two guards compose.</li>
 *   <li>{@code linger.ms} trades a few milliseconds of latency for far better
 *       batching; alerts are telemetry, not request-path writes.</li>
 * </ul>
 *
 * @author Satyendra Singh
 */
@Configuration(proxyBeanMethods = false)
public class KafkaConfig {

    /**
     * Producer factory serialising {@link FraudAlert} as JSON with the
     * application's {@link ObjectMapper}, so {@code java.time} values are
     * rendered as ISO-8601 rather than epoch arrays.
     *
     * @param kafkaProperties Spring Boot's bound {@code spring.kafka.*} settings
     * @param sslBundles      optional SSL bundle registry
     * @param objectMapper    the application-wide mapper
     * @param properties      SentinelGuard settings (client id / timeouts)
     * @return configured producer factory
     */
    @Bean
    public ProducerFactory<String, FraudAlert> fraudAlertProducerFactory(
            KafkaProperties kafkaProperties,
            ObjectProvider<SslBundles> sslBundles,
            ObjectMapper objectMapper,
            SentinelGuardProperties properties) {

        Map<String, Object> config =
                new HashMap<>(kafkaProperties.buildProducerProperties(sslBundles.getIfAvailable()));

        config.put(ProducerConfig.ACKS_CONFIG, "all");
        config.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, Boolean.TRUE);
        config.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 5);
        config.put(ProducerConfig.RETRIES_CONFIG, 10);
        config.put(ProducerConfig.RETRY_BACKOFF_MS_CONFIG, 100);
        config.put(ProducerConfig.LINGER_MS_CONFIG, 20);
        config.put(ProducerConfig.BATCH_SIZE_CONFIG, 32 * 1024);
        config.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "lz4");
        config.put(ProducerConfig.MAX_BLOCK_MS_CONFIG,
                Math.max(1_000L, properties.getAlerts().getSendTimeout().toMillis()));
        config.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 120_000);
        config.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30_000);
        config.putIfAbsent(ProducerConfig.CLIENT_ID_CONFIG, "sentinelguard-fraud-producer");

        JsonSerializer<FraudAlert> valueSerializer = new JsonSerializer<>(objectMapper);
        // Downstream consumers are polyglot; a Java-specific __TypeId__ header
        // would leak an implementation detail into a published contract.
        valueSerializer.setAddTypeInfo(false);

        return new DefaultKafkaProducerFactory<>(config, new StringSerializer(), valueSerializer);
    }

    /**
     * @param factory producer factory
     * @param properties SentinelGuard settings
     * @return template bound to the fraud-alert topic
     */
    @Bean
    public KafkaTemplate<String, FraudAlert> fraudAlertKafkaTemplate(
            ProducerFactory<String, FraudAlert> factory,
            SentinelGuardProperties properties) {

        KafkaTemplate<String, FraudAlert> template = new KafkaTemplate<>(factory);
        template.setDefaultTopic(properties.getAlerts().getTopic());
        template.setObservationEnabled(true);
        return template;
    }

    /**
     * Declares the alert topic so a cold environment (and the Testcontainers
     * integration run) needs no manual provisioning step. Partition count is
     * what bounds consumer-side parallelism, hence the generous default.
     *
     * @param properties SentinelGuard settings
     * @return topic definition applied by {@code KafkaAdmin} at startup
     */
    @Bean
    @ConditionalOnProperty(prefix = "sentinelguard.alerts", name = "auto-create-topic",
            havingValue = "true", matchIfMissing = true)
    public NewTopic fraudAlertsTopic(SentinelGuardProperties properties) {
        SentinelGuardProperties.Alerts alerts = properties.getAlerts();
        return TopicBuilder.name(alerts.getTopic())
                .partitions(alerts.getPartitions())
                .replicas(alerts.getReplicationFactor())
                .build();
    }
}
