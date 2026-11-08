/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.web;

import com.satyendra.sentinelguard.config.SentinelGuardProperties;
import com.satyendra.sentinelguard.domain.ClientIdentity;
import com.satyendra.sentinelguard.domain.IdentityType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Unit tests for {@link ClientIdentityResolver}: precedence, credential
 * hygiene and the forwarded-header trust switch.
 *
 * @author Satyendra Singh
 */
@DisplayName("ClientIdentityResolver")
class ClientIdentityResolverTest {

    private SentinelGuardProperties properties;
    private ClientIdentityResolver resolver;

    @BeforeEach
    void setUp() {
        properties = new SentinelGuardProperties();
        resolver = new ClientIdentityResolver(properties);
    }

    @Test
    @DisplayName("an API key outranks every weaker signal")
    void apiKeyWins() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest
                .get("/api/v1/transactions")
                .header("X-API-Key", "sk_live_super_secret")
                .header(HttpHeaders.AUTHORIZATION, "Bearer token-value")
                .header("X-Forwarded-For", "203.0.113.5")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 4444))
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.API_KEY);
        assertThat(identity.isCredentialBacked()).isTrue();
        assertThat(identity.asKeySegment()).startsWith("ak:");
    }

    @Test
    @DisplayName("credentials are never stored verbatim")
    void credentialsAreHashed() {
        String secret = "sk_live_super_secret";

        ClientIdentity identity = resolver.resolve(MockServerHttpRequest
                .get("/api/v1/transactions")
                .header("X-API-Key", secret)
                .build());

        assertThat(identity.value())
                .doesNotContain(secret)
                .hasSize(32)
                .matches("[0-9a-f]{32}");
    }

    @Test
    @DisplayName("the same credential always yields the same quota identity")
    void hashingIsStable() {
        ClientIdentity first = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-API-Key", "key-1").build());
        ClientIdentity second = resolver.resolve(MockServerHttpRequest.get("/b")
                .header("X-API-Key", "key-1").build());
        ClientIdentity other = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-API-Key", "key-2").build());

        assertThat(first.value()).isEqualTo(second.value());
        assertThat(first.value()).isNotEqualTo(other.value());
    }

    @Test
    @DisplayName("a bearer token is accepted case-insensitively and digested")
    void bearerTokenIsDigested() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a")
                .header(HttpHeaders.AUTHORIZATION, "bEaReR  jwt.payload.signature")
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.BEARER_SUBJECT);
        assertThat(identity.value()).doesNotContain("jwt.payload.signature");
        assertThat(identity.asKeySegment()).startsWith("bs:");
    }

    @Test
    @DisplayName("a non-bearer or empty Authorization header is ignored")
    void ignoresUnusableAuthorizationHeaders() {
        assertThat(resolver.resolve(MockServerHttpRequest.get("/a")
                .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build()).type()).isEqualTo(IdentityType.REMOTE_IP);

        assertThat(resolver.resolve(MockServerHttpRequest.get("/a")
                .header(HttpHeaders.AUTHORIZATION, "Bearer    ")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build()).type()).isEqualTo(IdentityType.REMOTE_IP);
    }

    @Test
    @DisplayName("a blank API key header falls through instead of minting a blank identity")
    void blankApiKeyFallsThrough() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-API-Key", "   ")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.REMOTE_IP);
    }

    @Test
    @DisplayName("the left-most forwarded hop is used when the header is trusted")
    void usesFirstForwardedHop() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-Forwarded-For", "203.0.113.5, 70.41.3.18, 150.172.238.178")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.FORWARDED_IP);
        assertThat(identity.value()).isEqualTo("203.0.113.5");
    }

    @Test
    @DisplayName("an untrusted forwarded header cannot be used to mint fresh quotas")
    void ignoresForwardedHeaderWhenUntrusted() {
        properties.getIdentity().setTrustForwardedHeaders(false);
        resolver = new ClientIdentityResolver(properties);

        MockServerHttpRequest request = MockServerHttpRequest.get("/a")
                .header("X-Forwarded-For", "203.0.113.5")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build();

        assertThat(resolver.resolve(request).type()).isEqualTo(IdentityType.REMOTE_IP);
        assertThat(resolver.resolve(request).value()).isEqualTo("10.0.0.1");
        assertThat(resolver.clientIp(request)).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("a blank forwarded header falls through to the socket address")
    void blankForwardedHeaderFallsThrough() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-Forwarded-For", " , ")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 1))
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.REMOTE_IP);
    }

    @Test
    @DisplayName("an exchange with no usable attribution becomes ANONYMOUS")
    void anonymousFallback() {
        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a").build());

        assertThat(identity.type()).isEqualTo(IdentityType.ANONYMOUS);
        assertThat(identity.isAnonymous()).isTrue();
        assertThat(identity.isCredentialBacked()).isFalse();
        assertThat(identity.value()).isEqualTo(ClientIdentity.ANONYMOUS_VALUE);
    }

    @Test
    @DisplayName("clientIp prefers the forwarded hop and degrades to 'unknown'")
    void clientIpResolution() {
        assertThat(resolver.clientIp(MockServerHttpRequest.get("/a")
                .header("X-Forwarded-For", "203.0.113.5")
                .build())).isEqualTo("203.0.113.5");

        assertThat(resolver.clientIp(MockServerHttpRequest.get("/a").build()))
                .isEqualTo("unknown");
    }

    @Test
    @DisplayName("a custom API key header name is honoured")
    void customHeaderName() {
        properties.getIdentity().setApiKeyHeader("X-Tenant-Token");
        resolver = new ClientIdentityResolver(properties);

        ClientIdentity identity = resolver.resolve(MockServerHttpRequest.get("/a")
                .header("X-Tenant-Token", "tenant-key")
                .build());

        assertThat(identity.type()).isEqualTo(IdentityType.API_KEY);
    }
}
