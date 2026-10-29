package com.securityanalyst.gateway.investigation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.securityanalyst.gateway.evidence.EvidenceService.RecordedSignal;

/**
 * Checks the agent's two reports against the evidence the gateway stored (step 13, ADR-45).
 * A report may only repeat what was recorded: every finding and reason must name a recorded
 * finding and use exactly its recorded words. The optional AI summary line is held to the
 * same rules as in the agent. Anything else means the agent is broken or compromised (ADR-5),
 * and the investigation ends in error. Messages never repeat the rejected text.
 */
final class ReportCheck {

    /** [E2], or several in one bracket: [E2, E1, E3]. */
    private static final Pattern CITATION = Pattern.compile("\\[(E[1-9][0-9]{0,2}(?:, ?E[1-9][0-9]{0,2})*)]");
    private static final List<Pattern> LOOKS_LIKE_INDICATOR = List.of(
            Pattern.compile("https?://|www\\.", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\S@\\S"),
            Pattern.compile("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b"),
            Pattern.compile("\\+?\\d[\\d ().-]{6,}\\d"),
            Pattern.compile("\\b[a-z0-9-]+(\\.[a-z0-9-]+)*\\.[a-z]{2,}\\b", Pattern.CASE_INSENSITIVE));
    private static final Pattern REASSURING = Pattern.compile("\\b(safe|benign|harmless|no threat"
            + "|not malicious|nothing suspicious|false positive|no risk)\\b", Pattern.CASE_INSENSITIVE);

    private ReportCheck() {
    }

    /** @param finalVerdict the verdict after the score floor, which the reports describe */
    static void check(AgentEvent.Report report, List<RecordedSignal> recorded, Set<String> evidence,
            String finalVerdict) {
        Map<String, RecordedSignal> byKey = new HashMap<>();
        recorded.forEach(signal -> byKey.put(signal.evidence() + "/" + signal.id(), signal));

        for (AgentEvent.ReportFinding finding : report.soc().findings()) {
            String key = finding.evidence() + "/" + finding.signal();
            RecordedSignal signal = byKey.get(key);
            if (signal == null) {
                throw new AgentException("The SOC report names " + key + ", which is not a recorded finding");
            }
            if (!signal.label().equals(finding.text()) || signal.weight() != finding.weight()
                    || !Objects.equals(signal.mitre(), finding.mitre())) {
                throw new AgentException("The SOC report does not repeat " + key + " as it was recorded");
            }
        }
        for (AgentEvent.ReportReason reason : report.plain().reasons()) {
            String key = reason.evidence() + "/" + reason.signal();
            RecordedSignal signal = byKey.get(key);
            if (signal == null) {
                throw new AgentException("The plain report names " + key + ", which is not a recorded finding");
            }
            if (!signal.plain().equals(reason.text())) {
                throw new AgentException("The plain report does not repeat " + key + " as it was recorded");
            }
        }
        Set<String> techniques = recorded.stream().map(RecordedSignal::mitre).filter(Objects::nonNull)
                .collect(Collectors.toSet());
        if (!techniques.containsAll(report.soc().techniques())) {
            throw new AgentException("The SOC report lists a technique no recorded finding has");
        }
        String line = report.soc().aiSummary();
        if (line != null) {
            checkSummary(line, evidence, finalVerdict);
        }
    }

    private static void checkSummary(String line, Set<String> evidence, String finalVerdict) {
        Matcher cited = CITATION.matcher(line);
        boolean any = false;
        while (cited.find()) {
            for (String label : cited.group(1).split(",")) {
                any = true;
                if (!evidence.contains(label.strip())) {
                    throw new AgentException("The AI summary cites " + label.strip() + ", which is not recorded evidence");
                }
            }
        }
        if (!any) {
            throw new AgentException("The AI summary cites no evidence");
        }
        if (line.contains("<") || line.contains(">") || LOOKS_LIKE_INDICATOR.stream().anyMatch(p -> p.matcher(line).find())) {
            throw new AgentException("The AI summary contains markup, an address, a link or a number");
        }
        if (!"benign".equals(finalVerdict) && REASSURING.matcher(line).find()) {
            throw new AgentException("The AI summary contradicts the verdict");
        }
    }
}
