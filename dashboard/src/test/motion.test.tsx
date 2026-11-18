import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../App";
import { EvidenceTimeline, IncidentHeader } from "../components/Investigation";
import { Overview } from "../components/Overview";
import { CountUp } from "../motion";
import { analyst, fakeGateway, incident, loggedInAs, summary } from "./fixtures";

const motion = (reduced: boolean) =>
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: reduced && query.includes("reduce"), media: query }));

afterEach(() => {
  vi.useRealTimers();
});

describe("numbers that count", () => {
  it("count up from 0 to the value when motion is allowed", () => {
    vi.useFakeTimers({ toFake: ["requestAnimationFrame", "cancelAnimationFrame", "performance"] });
    motion(false);
    const { container } = render(<CountUp value={90} />);

    expect(container.textContent).toBe("0");
    act(() => vi.advanceTimersByTime(250));
    const midway = Number(container.textContent);
    expect(midway).toBeGreaterThan(0);
    expect(midway).toBeLessThan(90);
    act(() => vi.advanceTimersByTime(600));
    expect(container.textContent).toBe("90");
  });

  it("are simply the number for visitors who asked for reduced motion", () => {
    motion(true);
    const { container, rerender } = render(<CountUp value={90} />);
    expect(container.textContent).toBe("90");
    rerender(<CountUp value={42} />);
    expect(container.textContent).toBe("42");
  });
});

describe("evidence arriving", () => {
  it("only a step found after the incident was opened slides in", () => {
    const first = { ...incident, evidence: incident.evidence.slice(0, 2) };
    const { rerender } = render(<EvidenceTimeline incident={first} highlighted={null} />);
    expect(document.querySelectorAll(".step-new")).toHaveLength(0);

    rerender(<EvidenceTimeline incident={incident} highlighted={null} />);

    const arrived = [...document.querySelectorAll(".step-new")].map((step) => step.id);
    expect(arrived).toEqual(incident.evidence.slice(2).map((step) => `evidence-${step.label}`));
  });

  it("the lattice runs, with a stopwatch from when the incident was submitted, only while it is still going", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.parse(incident.createdAt) + 12_400));
    const { rerender } = render(<IncidentHeader incident={{ ...incident, status: "investigating" }} />);
    const lattice = document.querySelector(".lattice-loader")!;
    expect(lattice).toHaveAttribute("data-status", "working");
    expect(lattice).toHaveTextContent("Investigating");
    expect(lattice.querySelector(".lattice-loader__timer")).toHaveTextContent("12.4s");

    rerender(<IncidentHeader incident={incident} />);
    expect(document.querySelector(".lattice-loader")).toBeNull();
  });
});

describe("loading", () => {
  it("shows placeholder shapes, read out as Loading, until the incidents arrive", () => {
    const { rerender } = render(<Overview incidents={null} audit={null} error={null} onOpen={() => {}} />);
    expect(screen.getByText("Loading...").closest("[aria-busy='true']")).not.toBeNull();
    expect(screen.queryByRole("region", { name: "Incidents" })).not.toBeInTheDocument();

    rerender(<Overview incidents={[summary]} audit={null} error={null} onOpen={() => {}} />);
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Incidents" })).toBeInTheDocument();
  });

  it("the incident page shows placeholders while the incident loads", async () => {
    const gateway = fakeGateway(loggedInAs(analyst));
    // The incident's answer never comes, so the page stays in its loading state.
    vi.stubGlobal("fetch", (url: string, init?: RequestInit) =>
      url === "/api/incidents/57" ? new Promise(() => {}) : gateway(url, init),
    );
    window.location.hash = "#/incidents/57";
    render(<App />);
    // Past the login check (the sidebar is there), the page itself is a placeholder.
    await screen.findByRole("navigation", { name: "Pages" });
    expect(document.querySelector(".skeleton-page[aria-busy='true']")).not.toBeNull();
    expect(screen.queryByRole("heading", { name: /#57/ })).not.toBeInTheDocument();
  });
});
