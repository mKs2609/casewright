import { describe, expect, it } from "vitest";

import { actionStatusMeaning, riskBand, statusMeaning, verdictMeaning } from "../meaning";

describe("risk bands (docs/DESIGN_SYSTEM.md)", () => {
  it.each([
    [0, "benign"],
    [29, "benign"],
    [30, "suspicious"],
    [64, "suspicious"],
    [65, "malicious"],
    [100, "malicious"],
  ])("a score of %i is %s", (score, band) => {
    expect(riskBand(score)).toBe(band);
  });
});

describe("states", () => {
  it.each(["queued", "investigating", "awaiting_approval", "needs_review", "closed", "error"])(
    "the incident status %s has its own word",
    (status) => {
      expect(statusMeaning(status).word).not.toBe("Unknown");
    },
  );

  it.each(["pending", "executed", "rejected", "expired"])("the action status %s has its own word", (status) => {
    expect(actionStatusMeaning(status).word).not.toBe("Unknown");
  });

  it("a state this version has never heard of still shows something, not a blank", () => {
    expect(statusMeaning("something_new").word).toBe("Unknown");
    expect(verdictMeaning("something_new").word).toBe("Unknown");
    expect(actionStatusMeaning("something_new").word).toBe("Unknown");
  });

  it("an executed action says it was simulated, because nothing real happens", () => {
    expect(actionStatusMeaning("executed").word).toContain("simulated");
  });
});
