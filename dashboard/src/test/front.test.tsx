import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FrontSections } from "../components/FrontSections";
import { Login } from "../components/Login";
import { SignalOrb } from "../components/SignalOrb";

describe("the login's dotted globe", () => {
  it("is a decoration hidden from screen readers, and copes when the canvas cannot draw", () => {
    const { container } = render(<SignalOrb />);
    expect(container.querySelector("canvas")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("the front page's sections", () => {
  it("shows how it investigates and the two reports, fully visible where the browser cannot watch scrolling", () => {
    const { container } = render(<FrontSections />);
    expect(screen.getByRole("heading", { name: /Four tools/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /explained twice/ })).toBeInTheDocument();
    expect(container.querySelectorAll(".reveal").length).toBeGreaterThan(0);
    expect(container.querySelectorAll(".reveal:not(.is-visible)")).toHaveLength(0);
  });

  it("shows the decision only as an example: there is nothing to click", () => {
    render(<FrontSections />);
    expect(screen.queryAllByRole("button")).toEqual([]);
    expect(screen.getByText(/Nothing happens until an analyst approves it/)).toBeInTheDocument();
  });

  it("names only reserved example sites and addresses (paypal.com only as the site being imitated)", () => {
    const { container } = render(<FrontSections />);
    // Each piece of text on its own, so neighbouring elements are not glued into one "word".
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const pieces: string[] = [];
    while (walker.nextNode()) {
      pieces.push(walker.currentNode.textContent ?? "");
    }
    const text = pieces.join(" ");
    const domains = (text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi) ?? []).filter((d) => !/^\d/.test(d));
    const addresses = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
    expect(domains.length + addresses.length).toBeGreaterThan(0);
    for (const domain of domains) {
      expect(domain === "paypal.com" || domain.endsWith(".example")).toBe(true);
    }
    for (const address of addresses) {
      expect(address).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
    }
    expect(text).not.toMatch(/paypal\.com (is|was) (known|malicious|on)/i);
  });
});

describe("the login page", () => {
  it("leads to the sections below with a button, not a link", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ signupOpen: true, demoLogin: false }))));
    const scrolled = vi.fn();
    Element.prototype.scrollIntoView = scrolled;
    render(<Login onLogin={() => {}} />);

    await userEvent.setup().click(screen.getByRole("button", { name: "See how it works" }));

    expect(scrolled).toHaveBeenCalledTimes(1);
    expect(scrolled.mock.contexts[0]).toHaveAttribute("id", "how-it-works");
  });
});
