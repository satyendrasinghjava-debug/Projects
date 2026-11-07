/*
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 */
package com.satyendra.sentinelguard.fraud;

import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * © 2026 Satyendra Singh. All Rights Reserved.
 * Author: Satyendra Singh
 *
 * Distributed sliding-window cardinality counter: the single primitive every
 * behavioural heuristic in this service is built on.
 *
 * @author Satyendra Singh
 */
public interface SlidingWindowCounter {

    /**
     * Records one observation and returns the number of <em>distinct</em>
     * members inside the window, including the one just recorded.
     *
     * <p>Member choice decides the semantics:</p>
     * <ul>
     *   <li>a unique member per call yields an <b>event count</b> (velocity);</li>
     *   <li>a repeating member such as a URI path yields a
     *       <b>distinct-value count</b> (enumeration).</li>
     * </ul>
     *
     * @param windowKey Redis key holding the window
     * @param member    identity of this observation
     * @param window    observation horizon
     * @param ttl       idle expiry of the window key
     * @return distinct member cardinality inside the window
     */
    Mono<Long> observe(String windowKey, String member, Duration window, Duration ttl);
}
