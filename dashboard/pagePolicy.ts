/**
 * The page's own security policy (the gateway's forbids everything, because it never serves pages).
 * Scripts and styles load only from this server, and requests go only to it. Nothing inline runs,
 * so text from an incident could not run as code even if it reached the page as HTML.
 */
export const PAGE_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** Only for `npm run dev`: hot reloading adds its scripts and styles inline. `npm run preview` has the real policy. */
export const DEV_PAGE_POLICY = PAGE_POLICY.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'").replace(
  "style-src 'self'",
  "style-src 'self' 'unsafe-inline'",
);

export const pageHeaders = (policy: string) => ({
  "Content-Security-Policy": policy,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
});
