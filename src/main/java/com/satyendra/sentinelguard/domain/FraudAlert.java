/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Immutable event published to the {@code fraud-alerts} Kafka topic. This is a
 * published contract: fields are only ever added, never renamed or removed, so
 * that downstream consumers can evolve independently.
 *
 * @param alertId       unique identifier of this alert
 * @param correlationId correlation id of the originating HTTP exchange
 * @param clientId      identity the risk is attributed to
 * @param identityType  provenance of {@code clientId}
 * @param clientIp      observed source address
 * @param httpMethod    HTTP method of the exchange
 * @param path          request path
 * @param userAgent     reported {@code User-Agent}, or {@code null}
 * @param policyName    rate-limit policy in force
 * @param riskScore     aggregated additive weight of {@code signals}
 * @param threatLevel   band derived from {@code riskScore}
 * @param signals       heuristics that fired, never empty
 * @param detectedAt    detection timestamp (UTC)
 * @author Satyendra Singh
 */
public record FraudAlert(
        String alertId,
        String correlationId,
        String clientId,
        IdentityType identityType,
        String clientIp,
        String httpMethod,
        String path,
        String userAgent,
        String policyName,
        int riskScore,
        ThreatLevel threatLevel,
        List<FraudSignal> signals,
        Instant detectedAt) {

    public FraudAlert {
        Objects.requireNonNull(alertId, "alertId must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(threatLevel, "threatLevel must not be null");
        Objects.requireNonNull(detectedAt, "detectedAt must not be null");
        signals = List.copyOf(Objects.requireNonNull(signals, "signals must not be null"));
        if (signals.isEmpty()) {
            throw new IllegalArgumentException("a fraud alert must carry at least one signal");
        }
    }

    /**
     * Factory used by the detection engine; mints the alert id and stamps the
     * aggregated score and band.
     *
     * @param fingerprint request under evaluation
     * @param policyName  policy in force
     * @param signals     heuristics that fired
     * @param riskScore   aggregated weight
     * @return fully populated alert
     */
    public static FraudAlert of(RequestFingerprint fingerprint, String policyName,
                                List<FraudSignal> signals, int riskScore) {
        return new FraudAlert(
                UUID.randomUUID().toString(),
                fingerprint.correlationId(),
                fingerprint.identity().value(),
                fingerprint.identity().type(),
                fingerprint.clientIp(),
                fingerprint.httpMethod(),
                fingerprint.path(),
                fingerprint.userAgent(),
                policyName,
                riskScore,
                ThreatLevel.fromScore(riskScore),
                signals,
                fingerprint.observedAt());
    }
}
