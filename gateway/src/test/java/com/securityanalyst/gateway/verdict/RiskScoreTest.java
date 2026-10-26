package com.securityanalyst.gateway.verdict;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Plain unit test. The same cases as the agent's tests/test_verdict.py: the two
 * implementations must agree exactly, or the gateway would report false disagreements.
 */
class RiskScoreTest {

    private static RiskScore.Finding f(String id, int weight) {
        return new RiskScore.Finding(id, weight);
    }

    @Test
    void theDesignDocsWorkedExample() {
        assertThat(RiskScore.of(List.of(f("AA", 50), f("BB", 45), f("CC", 25)))).isEqualTo(79);
    }

    @Test
    void theScamCallFromIncident12Scores71() {
        assertThat(RiskScore.of(List.of(f("SIG-OTP-REQ", 35), f("SIG-IMPERSONATION", 15), f("REP-MALICIOUS", 45),
                f("BASELINE-UNKNOWN-CALLER", 5)))).isEqualTo(71);
    }

    @Test
    void nothingFoundMeansZero() {
        assertThat(RiskScore.of(List.of())).isZero();
    }

    @Test
    void theSameKindOfFindingCountsOnceAtItsStrongest() {
        assertThat(RiskScore.of(List.of(f("REP-MALICIOUS", 45), f("REP-MALICIOUS", 45), f("REP-MALICIOUS", 20))))
                .isEqualTo(45);
    }

    @Test
    void noSingleFindingCountsAsCertainProof() {
        assertThat(RiskScore.of(List.of(f("AA", 100)))).isEqualTo(95);
    }

    @Test
    void theScoreNeverPasses100() {
        assertThat(RiskScore.of(IntStream.range(0, 20).mapToObj(i -> f("S" + i, 90)).toList())).isEqualTo(100);
    }

    @Test
    void halvesRoundUpExactlyAsTheAgentDoes() {
        // 50 and 25 give exactly 62.5. Half up gives 63, like the agent (Python's own round() would give 62).
        assertThat(RiskScore.of(List.of(f("AA", 50), f("BB", 25)))).isEqualTo(63);
        // 10 and 5 are really 14.500000000000002 in binary: 15 either way.
        assertThat(RiskScore.of(List.of(f("AA", 10), f("BB", 5)))).isEqualTo(15);
    }

    @Test
    void theOrderOfFindingsDoesNotChangeTheScore() {
        assertThat(RiskScore.of(List.of(f("ZZ", 13), f("AA", 7), f("MM", 29))))
                .isEqualTo(RiskScore.of(List.of(f("MM", 29), f("ZZ", 13), f("AA", 7))));
    }

    @ParameterizedTest
    @CsvSource({ "0,benign", "29,benign", "30,suspicious", "64,suspicious", "65,malicious", "100,malicious" })
    void theBands(int score, String band) {
        assertThat(RiskScore.band(score)).isEqualTo(band);
    }

    /** testdata/risk-score-cases.json is also checked by the agent's tests/test_verdict.py. */
    @Test
    void everySharedGoldenCaseMatches() throws Exception {
        JsonNode golden = JsonMapper.builder().build().readTree(Files.readString(Path.of("../testdata/risk-score-cases.json")));
        int checked = 0;
        for (JsonNode c : golden.get("cases")) {
            List<RiskScore.Finding> findings = new ArrayList<>();
            for (JsonNode pair : c.get("findings")) {
                findings.add(f(pair.get(0).asString(), pair.get(1).asInt()));
            }
            assertThat(RiskScore.of(findings)).as(c.get("why").asString()).isEqualTo(c.get("score").asInt());
            checked++;
        }
        assertThat(checked).isGreaterThan(40);
    }

    @Test
    void theMoreSevereVerdictWins() {
        assertThat(RiskScore.moreSevere("benign", "malicious")).isEqualTo("malicious");
        assertThat(RiskScore.moreSevere("suspicious", "benign")).isEqualTo("suspicious");
    }
}
