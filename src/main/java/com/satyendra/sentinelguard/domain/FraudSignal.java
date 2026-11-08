/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.domain;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Individual heuristic that can fire while scoring a request. Weights are
 * additive; the sum is classified by {@link ThreatLevel#fromScore(int)}.
 *
 * <p>Weights are deliberately tuned so that a single weak indicator cannot on
 * its own reach {@link ThreatLevel#MEDIUM} (the default publication floor),
 * while any two correlated indicators can. That keeps the
 * {@code fraud-alerts} topic signal-dense.</p>
 *
 * @author Satyendra Singh
 */
public enum FraudSignal {

    /** The caller exhausted its quota on this very request. */
    RATE_LIMIT_BREACH(25, "Request was rejected by the distributed token bucket"),

    /** Repeated rejections inside the observation window: a deliberate hammer. */
    BURST_VELOCITY(30, "Rejection velocity exceeded the configured burst threshold"),

    /** Many distinct paths from one identity: endpoint or object-id enumeration. */
    PATH_ENUMERATION(25, "Distinct path cardinality exceeded the configured threshold"),

    /** No {@code User-Agent} at all; almost never a real browser or SDK. */
    MISSING_USER_AGENT(15, "Request carried no User-Agent header"),

    /** {@code User-Agent} matches a known scripted-client pattern. */
    SUSPICIOUS_USER_AGENT(20, "User-Agent matched a known automation signature"),

    /** No credential presented, so the quota had to be charged to a network address. */
    ANONYMOUS_IDENTITY(10, "Caller presented no verifiable credential");

    private final int weight;
    private final String description;

    FraudSignal(int weight, String description) {
        this.weight = weight;
        this.description = description;
    }

    /** @return additive contribution of this signal to the risk score */
    public int weight() {
        return weight;
    }

    /** @return operator-facing explanation shipped with the alert */
    public String description() {
        return description;
    }
}
