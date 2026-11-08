/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Severity band derived from an aggregated fraud risk score. Declaration order
 * is significant: {@link #atLeast(ThreatLevel)} relies on it, and the
 * configured publication floor is compared ordinally.
 *
 * @author Satyendra Singh
 */
public enum ThreatLevel {

    /** No heuristic fired. */
    NONE(0),

    /** Weak signal; recorded for trend analysis only. */
    LOW(1),

    /** Worth an analyst's attention. */
    MEDIUM(30),

    /** Strong, correlated abuse indicators. */
    HIGH(55),

    /** Active, aggressive abuse. Page someone. */
    CRITICAL(80);

    private final int minimumScore;

    ThreatLevel(int minimumScore) {
        this.minimumScore = minimumScore;
    }

    /** @return inclusive lower bound of this band */
    public int minimumScore() {
        return minimumScore;
    }

    /**
     * Classifies an aggregated risk score.
     *
     * @param score non-negative aggregated weight of all fired signals
     * @return the highest band whose threshold the score reaches
     */
    public static ThreatLevel fromScore(int score) {
        ThreatLevel resolved = NONE;
        for (ThreatLevel candidate : values()) {
            if (score >= candidate.minimumScore) {
                resolved = candidate;
            }
        }
        return resolved;
    }

    /**
     * @param floor minimum band to compare against
     * @return {@code true} when this band is at least as severe as {@code floor}
     */
    public boolean atLeast(ThreatLevel floor) {
        return ordinal() >= floor.ordinal();
    }
}
