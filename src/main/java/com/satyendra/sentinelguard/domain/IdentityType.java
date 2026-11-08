/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Provenance of the identity a quota is charged against, ordered from the most
 * to the least trustworthy.
 *
 * <p>The {@link #shortCode()} is embedded in the Redis bucket key so that two
 * callers who happen to share a literal value (for example an API key whose
 * text equals an IP address) can never collide in the same bucket.</p>
 *
 * @author Satyendra Singh
 */
public enum IdentityType {

    /** Resolved from the configured API key header. Strongest signal. */
    API_KEY("ak", true),

    /** Derived from an {@code Authorization: Bearer} credential digest. */
    BEARER_SUBJECT("bs", true),

    /** First hop of a trusted {@code X-Forwarded-For} chain. */
    FORWARDED_IP("fw", false),

    /** Socket level peer address. */
    REMOTE_IP("ip", false),

    /** Nothing identifiable could be extracted from the exchange. */
    ANONYMOUS("an", false);

    private final String shortCode;
    private final boolean credentialBacked;

    IdentityType(String shortCode, boolean credentialBacked) {
        this.shortCode = shortCode;
        this.credentialBacked = credentialBacked;
    }

    /** @return compact, stable token used for Redis key namespacing */
    public String shortCode() {
        return shortCode;
    }

    /** @return {@code true} when the identity was proven by a presented credential */
    public boolean credentialBacked() {
        return credentialBacked;
    }
}
