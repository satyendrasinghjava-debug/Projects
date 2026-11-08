/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.config;

import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Cross-cutting infrastructure beans.
 *
 * @author Satyendra Singh
 */
@Configuration(proxyBeanMethods = false)
public class CoreConfig {

    /**
     * The single source of time for the whole engine.
     *
     * <p>Injecting a {@link Clock} rather than calling {@code Instant.now()}
     * inline is what allows the token-bucket refill arithmetic to be tested
     * deterministically with {@link Clock#fixed} instead of with sleeps.
     * UTC is mandatory: bucket watermarks are compared across hosts that may
     * sit in different zones.</p>
     *
     * @return UTC system clock
     */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Guarantees ISO-8601 timestamps in the published Kafka contract, so that
     * non-JVM consumers are not forced to parse epoch arrays.
     *
     * @return customiser applied to the application {@code ObjectMapper}
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer sentinelGuardJacksonCustomizer() {
        // Only features are touched here. Calling modules(...) would REPLACE the
        // auto-discovered module list and silently drop ParameterNamesModule,
        // which is what makes record deserialisation work.
        return builder -> builder
                .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }
}
