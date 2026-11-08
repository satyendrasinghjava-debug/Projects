/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.FraudAlert;
import com.satyendra.sentinelguard.domain.FraudSignal;
import com.satyendra.sentinelguard.domain.IdentityType;
import com.satyendra.sentinelguard.domain.ThreatLevel;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link KafkaFraudAlertPublisher}.
 *
 * @author Satyendra Singh
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("KafkaFraudAlertPublisher")
@SuppressWarnings({"unchecked", "rawtypes"})
class KafkaFraudAlertPublisherTest {

    @Mock
    private KafkaTemplate<String, FraudAlert> kafkaTemplate;

    private SentinelGuardProperties properties;
    private MeterRegistry meterRegistry;
    private KafkaFraudAlertPublisher publisher;

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        properties.getAlerts().setTopic("fraud-alerts");
        properties.getAlerts().setSendTimeout(Duration.ofSeconds(2));
        meterRegistry = new SimpleMeterRegistry();
        publisher = new KafkaFraudAlertPublisher(kafkaTemplate, properties, meterRegistry);
    }

    @Test
    @DisplayName("publishes to the configured topic, keyed by client identity")
    void publishesKeyedByIdentity() {
        doReturn(CompletableFuture.completedFuture(sendResult())).when(kafkaTemplate).send(any(ProducerRecord.class));
        ArgumentCaptor<ProducerRecord<String, FraudAlert>> captor =
                ArgumentCaptor.forClass(ProducerRecord.class);

        StepVerifier.create(publisher.publish(alert(ThreatLevel.HIGH, 55)))
                .verifyComplete();

        verify(kafkaTemplate).send(captor.capture());
        ProducerRecord<String, FraudAlert> published = captor.getValue();

        assertThat(published.topic()).isEqualTo("fraud-alerts");
        // Per-identity keying is what gives consumers causal ordering.
        assertThat(published.key()).isEqualTo("client-abc");
        assertThat(published.value().threatLevel()).isEqualTo(ThreatLevel.HIGH);

        assertThat(header(published, KafkaFraudAlertPublisher.HEADER_THREAT_LEVEL)).isEqualTo("HIGH");
        assertThat(header(published, KafkaFraudAlertPublisher.HEADER_RISK_SCORE)).isEqualTo("55");
        assertThat(header(published, KafkaFraudAlertPublisher.HEADER_CORRELATION_ID))
                .isEqualTo("corr-77");

        assertThat(publishCount("published", ThreatLevel.HIGH)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("a broker failure is absorbed so customer traffic is never affected")
    void brokerFailureIsAbsorbed() {
        doReturn(CompletableFuture.failedFuture(new IllegalStateException("no brokers")))
                .when(kafkaTemplate).send(any(ProducerRecord.class));

        StepVerifier.create(publisher.publish(alert(ThreatLevel.CRITICAL, 110)))
                .verifyComplete();

        assertThat(publishCount("failed", ThreatLevel.CRITICAL)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("a synchronous send failure is absorbed as well")
    void synchronousFailureIsAbsorbed() {
        doReturn(null).when(kafkaTemplate).send(any(ProducerRecord.class));

        // Mono.fromFuture(null) raises immediately; the publisher must still complete.
        StepVerifier.create(publisher.publish(alert(ThreatLevel.MEDIUM, 35)))
                .verifyComplete();

        assertThat(publishCount("failed", ThreatLevel.MEDIUM)).isEqualTo(1.0d);
    }

    @Test
    @DisplayName("a stalled broker is abandoned after the configured send timeout")
    void stalledSendTimesOut() {
        properties.getAlerts().setSendTimeout(Duration.ofMillis(100));
        doReturn(new CompletableFuture<SendResult<String, FraudAlert>>())
                .when(kafkaTemplate).send(any(ProducerRecord.class));

        StepVerifier.create(publisher.publish(alert(ThreatLevel.HIGH, 55)))
                .expectSubscription()
                .expectComplete()
                .verify(Duration.ofSeconds(5));

        assertThat(publishCount("failed", ThreatLevel.HIGH)).isEqualTo(1.0d);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static String header(ProducerRecord<String, FraudAlert> record, String name) {
        return new String(record.headers().lastHeader(name).value(), StandardCharsets.UTF_8);
    }

    private double publishCount(String outcome, ThreatLevel threatLevel) {
        return meterRegistry.get("sentinelguard.fraud.alerts.published")
                .tag("outcome", outcome)
                .tag("threat", threatLevel.name())
                .counter()
                .count();
    }

    private static SendResult<String, FraudAlert> sendResult() {
        ProducerRecord<String, FraudAlert> record =
                new ProducerRecord<>("fraud-alerts", "client-abc", alert(ThreatLevel.HIGH, 55));
        RecordMetadata metadata = new RecordMetadata(
                new TopicPartition("fraud-alerts", 3), 42L, 0, 0L, 0, 0);
        return new SendResult<>(record, metadata);
    }

    private static FraudAlert alert(ThreatLevel threatLevel, int riskScore) {
        return new FraudAlert("alert-1", "corr-77", "client-abc", IdentityType.API_KEY,
                "203.0.113.9", "POST", "/api/v1/transactions", "curl/8.7.1", "payments-strict",
                riskScore, threatLevel, List.of(FraudSignal.RATE_LIMIT_BREACH),
                Instant.parse("2026-05-05T05:05:05Z"));
    }
}
