/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import com.satyendra.sentinelguard.domain.FraudAlert;
import reactor.core.publisher.Mono;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Transport abstraction for outbound fraud alerts.
 *
 * <p>Implementations must absorb their own transport failures: alerting is a
 * side channel and must never be able to fail a customer request.</p>
 *
 * @author Satyendra Singh
 */
public interface FraudAlertPublisher {

    /**
     * Publishes an alert asynchronously.
     *
     * @param alert alert to publish
     * @return completion signal; completes empty even when the transport failed
     */
    Mono<Void> publish(FraudAlert alert);
}
