import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { DEV_PAGE_POLICY, PAGE_POLICY, caddyHeaderLines, pageHeaders } from "../../pagePolicy";

const DASHBOARD = resolve(import.meta.dirname, "../..");
const SRC = join(DASHBOARD, "src");

function filesIn(folder: string): string[] {
  return readdirSync(folder).flatMap((name) => {
    const path = join(folder, name);
    return statSync(path).isDirectory() ? filesIn(path) : [path];
  });
}

const product = filesIn(SRC).filter((path) => !path.includes(join("src", "test")));
const code = product.filter((path) => /\.tsx?$/.test(path));
const read = (path: string) => readFileSync(path, "utf8");

/** The checks below scan source files, so first prove they are really reading them. */
it("the rule checks are looking at the real source", () => {
  expect(code.some((path) => path.endsWith("App.tsx"))).toBe(true);
  expect(product.some((path) => path.endsWith("app.css"))).toBe(true);
});

describe("project rules", () => {
  it.each(["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("])(
    "the product code never uses %s",
    (banned) => {
      expect(code.filter((path) => read(path).includes(banned))).toEqual([]);
    },
  );

  it("no link is built in the product code", () => {
    expect(code.filter((path) => /<a[\s>]|href=/.test(read(path)))).toEqual([]);
  });

  it("nothing is kept in browser storage: the session lives only in cookies the page cannot read", () => {
    expect(code.filter((path) => /localStorage|sessionStorage|document\.cookie|indexedDB/.test(read(path)))).toEqual([]);
  });

  it("colours and durations come only from the tokens", () => {
    const styles = read(join(SRC, "styles/app.css"));
    expect(styles.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g)).toBeNull();
    expect(styles.match(/\b\d+m?s\b/g)).toBeNull();
    const inCode = code.filter((path) => /#[0-9a-fA-F]{6}\b|\brgba?\(/.test(read(path)));
    expect(inCode).toEqual([]);
  });

  it("sizes in the styles come only from the tokens (screen widths for the layout are the one exception)", () => {
    const styles = read(join(SRC, "styles/app.css")).replace(/@media[^{]+\{/g, "");
    expect(styles.match(/\b[1-9]\d*(px|rem|em)\b/g)).toBeNull();
  });

  it("the product name stays out of the code's identifiers (ADR-30): only what people read may use it", () => {
    const named = code.filter((path) => /\bcasewright\b/.test(read(path)));
    expect(named).toEqual([]);
  });

  it("no setting reaches the page from the environment", () => {
    expect(code.filter((path) => /import\.meta\.env|process\.env/.test(read(path)))).toEqual([]);
  });
});

describe("the page's security policy", () => {
  const directive = (policy: string, name: string) => policy.split("; ").find((part) => part.startsWith(`${name} `));

  it("denies everything unless named", () => {
    expect(directive(PAGE_POLICY, "default-src")).toBe("default-src 'none'");
  });

  it("runs no inline code, and no code from elsewhere", () => {
    expect(PAGE_POLICY).not.toContain("unsafe");
    expect(directive(PAGE_POLICY, "script-src")).toBe("script-src 'self'");
    expect(directive(PAGE_POLICY, "connect-src")).toBe("connect-src 'self'");
  });

  it("cannot be framed, redirected by a base tag, or used to post a form elsewhere", () => {
    expect(directive(PAGE_POLICY, "frame-ancestors")).toBe("frame-ancestors 'none'");
    expect(directive(PAGE_POLICY, "base-uri")).toBe("base-uri 'none'");
    expect(directive(PAGE_POLICY, "form-action")).toBe("form-action 'none'");
  });

  it("the looser policy only adds inline code for hot reloading, and is used by the dev server alone", () => {
    expect(DEV_PAGE_POLICY.replaceAll(" 'unsafe-inline'", "")).toBe(PAGE_POLICY);
    const config = read(join(DASHBOARD, "vite.config.ts"));
    expect(config).toMatch(/preview: \{[^\n]*pageHeaders\(PAGE_POLICY\)/);
    expect(config).toMatch(/server: \{[^\n]*pageHeaders\(DEV_PAGE_POLICY\)/);
  });

  it("is the policy production sends too, written as Caddyfile lines", () => {
    const lines = caddyHeaderLines(PAGE_POLICY);
    expect(lines).toContain(`header Content-Security-Policy "${PAGE_POLICY}"\n`);
    expect(lines.trim().split("\n")).toHaveLength(Object.keys(pageHeaders(PAGE_POLICY)).length);
    // A double quote inside a value would end it early in the Caddyfile.
    expect(Object.values(pageHeaders(PAGE_POLICY)).join("")).not.toContain('"');
    const dockerfile = read(join(DASHBOARD, "..", "deploy", "caddy.Dockerfile"));
    expect(dockerfile).toMatch(/node scripts\/page-headers\.ts > \S*page-headers\.caddy/);
  });

  it("is sent with the other protective headers", () => {
    expect(pageHeaders(PAGE_POLICY)).toMatchObject({
      "Content-Security-Policy": PAGE_POLICY,
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    });
  });

  it("the gateway's certificate is checked by the proxy, never switched off", () => {
    const config = read(join(DASHBOARD, "vite.config.ts"));
    expect(config).toContain("secure: true");
    expect(config).not.toContain("secure: false");
    expect(config).not.toContain("rejectUnauthorized");
  });
});
