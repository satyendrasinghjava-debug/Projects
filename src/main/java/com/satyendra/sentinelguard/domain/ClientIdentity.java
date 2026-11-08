/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

import java.util.Objects;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Immutable identity a request is attributed to for quota and risk accounting.
 *
 * @param value opaque, already-normalised identity value (never a raw secret)
 * @param type  how the value was obtained
 * @author Satyendra Singh
 */
public record ClientIdentity(String value, IdentityType type) {

    /** Canonical value used when no identity could be resolved at all. */
    public static final String ANONYMOUS_VALUE = "anonymous";

    /**
     * @throws NullPointerException     if any component is {@code null}
     * @throws IllegalArgumentException if {@code value} is blank
     */
    public ClientIdentity {
        Objects.requireNonNull(value, "identity value must not be null");
        Objects.requireNonNull(type, "identity type must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("identity value must not be blank");
        }
    }

    /** @return the singleton-shaped anonymous identity */
    public static ClientIdentity anonymous() {
        return new ClientIdentity(ANONYMOUS_VALUE, IdentityType.ANONYMOUS);
    }

    /** @return {@code true} when no identity could be resolved */
    public boolean isAnonymous() {
        return type == IdentityType.ANONYMOUS;
    }

    /** @return {@code true} when the caller presented a credential */
    public boolean isCredentialBacked() {
        return type.credentialBacked();
    }

    /** @return {@code <shortCode>:<value>}, the identity segment of a Redis key */
    public String asKeySegment() {
        return type.shortCode() + ':' + value;
    }
}
