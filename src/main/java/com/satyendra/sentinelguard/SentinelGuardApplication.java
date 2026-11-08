/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * <h2>SentinelGuard</h2>
 *
 * Entry point of the <strong>SentinelGuard</strong> edge service: a fully
 * non-blocking Spring WebFlux application that fuses two concerns normally
 * bolted on separately at the edge of a platform:
 *
 * <ol>
 *   <li><b>Distributed rate limiting</b> &mdash; a Redis-backed token bucket
 *       whose read-modify-write cycle is executed inside a single atomic Lua
 *       script, so horizontally scaled replicas share one authoritative
 *       quota without a distributed lock and without lost-update races.</li>
 *   <li><b>Fraud detection</b> &mdash; behavioural heuristics evaluated over
 *       atomic Redis sliding windows, with scored alerts streamed
 *       asynchronously to the {@code fraud-alerts} Kafka topic so that the
 *       request path is never coupled to downstream analytics latency.</li>
 * </ol>
 *
 * <h3>Threading contract</h3>
 * Nothing in this service may block an event-loop thread. All I/O travels
 * through Lettuce's reactive API or is explicitly offloaded to
 * {@code Schedulers.boundedElastic()} (see the Kafka publisher), and no
 * {@code block()} call exists anywhere in the production source set.
 *
 * @author Satyendra Singh
 * @since 1.0.0
 */
@SpringBootApplication
@EnableConfigurationProperties(SentinelGuardProperties.class)
public class SentinelGuardApplication {

    /**
     * Boots the reactive Netty server.
     *
     * @param args standard Spring Boot command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(SentinelGuardApplication.class, args);
    }
}
