package com.securityanalyst.gateway.verdict;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The risk score and its band (AGENT_DESIGN section 6, ADR-9): the same rules as the
 * agent's verdict.py, recomputed here from the evidence the gateway stored, so a confused or
 * compromised agent cannot claim a lower risk than its own evidence shows.
 *
 * The two implementations must agree exactly, so both multiply the findings in the same
 * order (sorted by id) and round halves up (14.5 becomes 15).
 */
public final class RiskScore {

    /** One finding: what kind it is, and how strongly it points to an attack (0-100). */
    public record Finding(String id, int weight) {
    }

    /** No single finding is treated as certain proof. */
    static final int MAX_WEIGHT = 95;

    private RiskScore() {
    }

    /** Noisy-OR over the strongest finding of each kind: 100 x (1 - product of (1 - weight/100)). */
    public static int of(List<Finding> findings) {
        Map<String, Integer> strongest = new TreeMap<>();   // sorted by id, like the agent
        for (Finding f : findings) {
            strongest.merge(f.id(), f.weight(), Math::max);
        }
        double allFalseAlarms = 1.0;
        for (int weight : strongest.values()) {
            allFalseAlarms *= 1 - Math.min(weight, MAX_WEIGHT) / 100.0;
        }
        return (int) Math.floor(100 * (1 - allFalseAlarms) + 0.5);
    }

    /** 0-29 benign, 30-64 suspicious, 65-100 malicious. */
    public static String band(int score) {
        return score < 30 ? "benign" : score < 65 ? "suspicious" : "malicious";
    }

    /** benign < suspicious < malicious. */
    public static int severity(String verdict) {
        return switch (verdict) {
            case "benign" -> 0;
            case "suspicious" -> 1;
            case "malicious" -> 2;
            default -> throw new IllegalArgumentException("Unknown verdict");
        };
    }

    /** The more severe of two verdicts. */
    public static String moreSevere(String a, String b) {
        return List.of(a, b).stream().max(Comparator.comparingInt(RiskScore::severity)).orElseThrow();
    }
}
