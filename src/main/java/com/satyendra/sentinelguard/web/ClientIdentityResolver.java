/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Derives the identity a quota is charged to, strongest signal first.
 *
 * <h3>Precedence</h3>
 * <ol>
 *   <li>API key header &rarr; {@link IdentityType#API_KEY}</li>
 *   <li>{@code Authorization: Bearer} &rarr; {@link IdentityType#BEARER_SUBJECT}</li>
 *   <li>First hop of a <em>trusted</em> forwarded chain &rarr; {@link IdentityType#FORWARDED_IP}</li>
 *   <li>Socket peer address &rarr; {@link IdentityType#REMOTE_IP}</li>
 *   <li>Nothing usable &rarr; {@link IdentityType#ANONYMOUS}</li>
 * </ol>
 *
 * <h3>Credentials are never stored verbatim</h3>
 * API keys and bearer tokens are reduced to a truncated SHA-256 digest before
 * they become part of a Redis key or a Kafka payload. Redis keys surface in
 * {@code SLOWLOG}, {@code MONITOR}, RDB snapshots and backups; a raw bearer
 * token in any of those is a credential leak. The digest is still a stable,
 * unique quota identity, so nothing is lost.
 *
 * <h3>Forwarded headers are opt-in</h3>
 * {@code X-Forwarded-For} is attacker-controlled unless a trusted proxy
 * overwrites it. With {@code trust-forwarded-headers=false} the resolver falls
 * back to the socket address, which a client cannot forge, at the cost of
 * conflating callers behind one NAT.
 *
 * @author Satyendra Singh
 */
@Component
public class ClientIdentityResolver {

    private static final String BEARER_PREFIX = "bearer ";
    private static final int DIGEST_LENGTH = 32;
    private static final String UNRESOLVED_IP = "unknown";

    private final SentinelGuardProperties.Identity config;

    /**
     * @param properties engine configuration
     */
    public ClientIdentityResolver(SentinelGuardProperties properties) {
        this.config = properties.getIdentity();
    }

    /**
     * @param request inbound request
     * @return the resolved identity; never {@code null}
     */
    public ClientIdentity resolve(ServerHttpRequest request) {
        HttpHeaders headers = request.getHeaders();

        String apiKey = trimToNull(headers.getFirst(config.getApiKeyHeader()));
        if (apiKey != null) {
            return new ClientIdentity(digest(apiKey), IdentityType.API_KEY);
        }

        String bearerSubject = bearerSubject(headers.getFirst(HttpHeaders.AUTHORIZATION));
        if (bearerSubject != null) {
            return new ClientIdentity(bearerSubject, IdentityType.BEARER_SUBJECT);
        }

        if (config.isTrustForwardedHeaders()) {
            String forwarded = firstForwardedHop(headers.getFirst(config.getForwardedHeader()));
            if (forwarded != null) {
                return new ClientIdentity(forwarded, IdentityType.FORWARDED_IP);
            }
        }

        String remoteAddress = socketAddress(request);
        if (remoteAddress != null) {
            return new ClientIdentity(remoteAddress, IdentityType.REMOTE_IP);
        }

        return ClientIdentity.anonymous();
    }

    /**
     * Best-effort source address for logging and alert enrichment. Unlike
     * {@link #resolve}, this never falls back to a credential digest.
     *
     * @param request inbound request
     * @return source address, or {@code "unknown"}
     */
    public String clientIp(ServerHttpRequest request) {
        if (config.isTrustForwardedHeaders()) {
            String forwarded = firstForwardedHop(
                    request.getHeaders().getFirst(config.getForwardedHeader()));
            if (forwarded != null) {
                return forwarded;
            }
        }
        String socketAddress = socketAddress(request);
        return socketAddress != null ? socketAddress : UNRESOLVED_IP;
    }

    /**
     * @param authorizationHeader raw {@code Authorization} header value
     * @return truncated digest of the bearer credential, or {@code null}
     */
    private String bearerSubject(String authorizationHeader) {
        String header = trimToNull(authorizationHeader);
        if (header == null || !header.toLowerCase(Locale.ROOT).startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : digest(token);
    }

    /**
     * @param headerValue raw forwarded header, possibly a comma separated chain
     * @return the left-most (original client) hop, or {@code null}
     */
    private String firstForwardedHop(String headerValue) {
        String header = trimToNull(headerValue);
        if (header == null) {
            return null;
        }
        int separator = header.indexOf(',');
        String firstHop = (separator < 0 ? header : header.substring(0, separator)).trim();
        return firstHop.isEmpty() ? null : firstHop;
    }

    /**
     * @param request inbound request
     * @return the socket peer address, or {@code null} when unavailable
     */
    private String socketAddress(ServerHttpRequest request) {
        InetSocketAddress remote = request.getRemoteAddress();
        if (remote == null) {
            return null;
        }
        if (remote.getAddress() != null) {
            return remote.getAddress().getHostAddress();
        }
        // Unresolved address: fall back to the host name string rather than
        // throwing, so a proxied request is still attributable.
        return trimToNull(remote.getHostString());
    }

    /**
     * @param value secret material
     * @return first {@value #DIGEST_LENGTH} hex characters of its SHA-256 digest
     */
    private String digest(String value) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, DIGEST_LENGTH);
        } catch (NoSuchAlgorithmException cause) {
            // SHA-256 is mandated by the JCA specification; unreachable on any
            // compliant JVM, so this is a fatal environment fault.
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", cause);
        }
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
