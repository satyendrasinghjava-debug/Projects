/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.domain.RequestFingerprint;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Converts a {@link ServerWebExchange} into the transport-agnostic
 * {@link RequestFingerprint} the engine reasons about.
 *
 * <p>This is the only seam in the service that knows about the HTTP stack.
 * Everything downstream is therefore unit-testable without a mock server.</p>
 *
 * @author Satyendra Singh
 */
@Component
public class RequestFingerprintFactory {

    private final ClientIdentityResolver identityResolver;
    private final Clock clock;

    /**
     * @param identityResolver identity extraction strategy
     * @param clock            UTC clock
     */
    public RequestFingerprintFactory(ClientIdentityResolver identityResolver, Clock clock) {
        this.identityResolver = identityResolver;
        this.clock = clock;
    }

    /**
     * @param exchange current exchange
     * @return normalised, immutable request metadata
     */
    public RequestFingerprint create(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        return new RequestFingerprint(
                correlationId(exchange),
                identityResolver.resolve(request),
                identityResolver.clientIp(request),
                request.getMethod().name(),
                request.getPath().value(),
                request.getHeaders().getFirst(HttpHeaders.USER_AGENT),
                Instant.now(clock));
    }

    /**
     * Resolves the correlation id established by {@link CorrelationIdWebFilter},
     * minting one if this factory is used outside that filter chain (for
     * instance from a controller in a narrow slice test).
     *
     * @param exchange current exchange
     * @return non-null correlation id
     */
    private String correlationId(ServerWebExchange exchange) {
        Object attribute = exchange.getAttribute(CorrelationIdWebFilter.CORRELATION_ID_ATTRIBUTE);
        if (attribute instanceof String correlationId && !correlationId.isBlank()) {
            return correlationId;
        }
        return UUID.randomUUID().toString();
    }
}
