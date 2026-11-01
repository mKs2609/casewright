package com.securityanalyst.gateway.action;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.securityanalyst.gateway.evidence.EvidenceService.RecordedSignal;

/**
 * Which proposals are allowed (AGENT_DESIGN section 9, ADR-47). The agent's proposals are not
 * trusted: the risk is decided here, and each target is checked against what this incident
 * actually contains and what was actually found. Reasons are in our words, never repeating a value.
 */
final class ActionPolicy {

    static final Set<String> IDENTITY_ACTIONS = Set.of("monitor", "notify_user", "force_password_reset", "lock_account");
    private static final Set<String> LOW_RISK = Set.of("monitor", "notify_user");

    /** What this incident contains and what was found. Its values come from what the gateway stored. */
    record Context(String finalVerdict, Set<String> identities, Map<String, Set<String>> indicators, String sender,
            String callerNumber, List<RecordedSignal> signals, Set<String> evidenceLabels, List<String> protectedDomains) {
    }

    private ActionPolicy() {
    }

    static String risk(String action) {
        return LOW_RISK.contains(action) ? "low" : "high";
    }

    /** Why this proposal is refused, or null if it is allowed. */
    static String refusal(String action, String target, String evidence, Context context) {
        if (!context.evidenceLabels().contains(evidence)) {
            return "it cites evidence that does not exist";
        }
        if (!LOW_RISK.contains(action) && "benign".equals(context.finalVerdict())) {
            return "a high-risk action cannot follow a benign verdict";
        }
        return switch (action) {
            case "monitor" -> context.identities().contains(target) || isIndicator(target, context)
                    ? null : "the target is not part of the incident";
            case "notify_user" -> context.identities().contains(target) ? null : "the target is not a person in the incident";
            case "force_password_reset", "lock_account" -> !context.identities().contains(target)
                    ? "the target is not a person in the incident"
                    : hasFinding(evidence, context) ? null : "the evidence has no finding";
            case "block_ip" -> !type(context, "ip").contains(target) ? "the address is not in the incident"
                    : isInternal(target) ? "internal addresses can never be blocked"
                    : findingAbout(target, evidence, context) ? null : "the evidence has no finding about this address";
            case "block_sender_domain" -> !type(context, "domain").contains(target) ? "the domain is not in the incident"
                    : isProtected(target, context.protectedDomains()) ? "a protected domain can never be blocked"
                    : findingAbout(target, evidence, context) ? null : "the evidence has no finding about this domain";
            case "block_phone_number" -> !target.equals(context.callerNumber()) ? "the number is not the caller's"
                    : findingAbout(target, evidence, context) ? null : "the evidence has no finding about this number";
            case "quarantine_email" -> !target.equals(context.sender()) ? "the target is not the sender"
                    : hasFinding(evidence, context) ? null : "the evidence has no finding";
            default -> "the action is not on the allow-list";
        };
    }

    private static Set<String> type(Context context, String type) {
        return context.indicators().getOrDefault(type, Set.of());
    }

    private static boolean isIndicator(String target, Context context) {
        return context.indicators().values().stream().anyMatch(values -> values.contains(target));
    }

    private static boolean hasFinding(String evidence, Context context) {
        return context.signals().stream().anyMatch(s -> s.evidence().equals(evidence) && s.weight() > 0);
    }

    private static boolean findingAbout(String target, String evidence, Context context) {
        return context.signals().stream()
                .anyMatch(s -> s.evidence().equals(evidence) && s.weight() > 0 && target.equals(s.indicator()));
    }

    /** The same networks as the agent's threat_intel.is_internal_address. Documentation ranges are not among them. */
    static boolean isInternal(String ip) {
        InetAddress address = InetAddress.ofLiteral(ip);
        byte first = address.getAddress()[0];
        return address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress()
                || address.isAnyLocalAddress() || (address.getAddress().length == 16 && (first & 0xfe) == 0xfc);
    }

    /** The domain itself or any of its subdomains. */
    static boolean isProtected(String domain, List<String> protectedDomains) {
        String lower = domain.toLowerCase(Locale.ROOT);
        return protectedDomains.stream().map(p -> p.toLowerCase(Locale.ROOT))
                .anyMatch(p -> lower.equals(p) || lower.endsWith("." + p));
    }
}
