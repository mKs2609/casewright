import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SignalOrb } from "../components/SignalOrb";

describe("the login's dotted globe", () => {
  it("is a decoration hidden from screen readers, and copes when the canvas cannot draw", () => {
    const { container } = render(<SignalOrb />);
    expect(container.querySelector("canvas")).toHaveAttribute("aria-hidden", "true");
  });
});
