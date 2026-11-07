/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.FraudAlert;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Asynchronous Kafka producer for the {@code fraud-alerts} topic.
 *
 * <h3>Keying</h3>
 * The record key is the client identity, so every alert for one caller lands on
 * one partition and therefore reaches consumers in causal order. That is what
 * lets a downstream stream processor build a per-identity state machine
 * ("three MEDIUM alerts in a minute ⇒ auto-block") without a repartition step.
 *
 * <h3>Why the scheduler hop</h3>
 * {@code KafkaProducer#send} is only <em>mostly</em> asynchronous: it blocks the
 * calling thread while topic metadata is unknown or while the record
 * accumulator is full. Blocking a Netty event loop there would stall unrelated
 * requests, so the call is published on
 * {@link Schedulers#boundedElastic()} and additionally capped by a timeout.
 *
 * <h3>Why failures are swallowed</h3>
 * This is telemetry, not a request-path write. A broker outage must degrade
 * visibility, never customer traffic, so transport faults are counted, logged
 * and dropped rather than propagated.
 *
 * @author Satyendra Singh
 */
@Component
public class KafkaFraudAlertPublisher implements FraudAlertPublisher {

    private static final Logger log = LoggerFactory.getLogger(KafkaFraudAlertPublisher.class);

    private static final String PUBLISH_METRIC = "sentinelguard.fraud.alerts.published";

    /** Threat band, exposed as a header so consumers can route without parsing the body. */
    public static final String HEADER_THREAT_LEVEL = "X-Sentinel-Threat-Level";

    /** Risk score, exposed as a header for cheap filtering. */
    public static final String HEADER_RISK_SCORE = "X-Sentinel-Risk-Score";

    /** Correlation id tying the alert back to the originating HTTP exchange. */
    public static final String HEADER_CORRELATION_ID = "X-Sentinel-Correlation-Id";

    private final KafkaTemplate<String, FraudAlert> kafkaTemplate;
    private final SentinelGuardProperties properties;
    private final MeterRegistry meterRegistry;

    /**
     * @param kafkaTemplate idempotent, JSON-serialising template
     * @param properties    engine configuration (topic, send timeout)
     * @param meterRegistry Micrometer registry
     */
    public KafkaFraudAlertPublisher(KafkaTemplate<String, FraudAlert> kafkaTemplate,
                                    SentinelGuardProperties properties,
                                    MeterRegistry meterRegistry) {
        this.kafkaTemplate = kafkaTemplate;
        this.properties = properties;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public Mono<Void> publish(FraudAlert alert) {
        SentinelGuardProperties.Alerts config = properties.getAlerts();

        return Mono.defer(() -> Mono.fromFuture(kafkaTemplate.send(toRecord(config.getTopic(), alert))))
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(config.getSendTimeout())
                .doOnSuccess(result -> onPublished(alert, result))
                .onErrorResume(error -> {
                    count(alert, "failed");
                    log.warn("Failed to publish fraud alert [alertId={}, clientId={}, threat={}] "
                                    + "to topic '{}'. Customer traffic is unaffected.",
                            alert.alertId(), alert.clientId(), alert.threatLevel(),
                            config.getTopic(), error);
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Builds the record, attaching routing headers alongside the JSON body.
     *
     * @param topic destination topic
     * @param alert alert to serialise
     * @return producer record keyed by client identity
     */
    private ProducerRecord<String, FraudAlert> toRecord(String topic, FraudAlert alert) {
        ProducerRecord<String, FraudAlert> alertRecord =
                new ProducerRecord<>(topic, alert.clientId(), alert);

        alertRecord.headers()
                .add(new RecordHeader(HEADER_THREAT_LEVEL,
                        alert.threatLevel().name().getBytes(StandardCharsets.UTF_8)))
                .add(new RecordHeader(HEADER_RISK_SCORE,
                        Integer.toString(alert.riskScore()).getBytes(StandardCharsets.UTF_8)))
                .add(new RecordHeader(HEADER_CORRELATION_ID,
                        String.valueOf(alert.correlationId()).getBytes(StandardCharsets.UTF_8)));

        return alertRecord;
    }

    private void onPublished(FraudAlert alert, SendResult<String, FraudAlert> result) {
        count(alert, "published");
        if (log.isInfoEnabled()) {
            log.info("Fraud alert dispatched [alertId={}, clientId={}, threat={}, score={}, "
                            + "signals={}] -> {}-{}@{}",
                    alert.alertId(), alert.clientId(), alert.threatLevel(), alert.riskScore(),
                    alert.signals(), result.getRecordMetadata().topic(),
                    result.getRecordMetadata().partition(), result.getRecordMetadata().offset());
        }
    }

    private void count(FraudAlert alert, String outcome) {
        Counter.builder(PUBLISH_METRIC)
                .description("Fraud alerts handed to the Kafka transport")
                .tag("outcome", outcome)
                .tag("threat", alert.threatLevel().name())
                .register(meterRegistry)
                .increment();
    }
}
