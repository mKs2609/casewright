// Prints the page's security headers as Caddyfile lines (step 19a). Run by the web server's image
// build (deploy/caddy.Dockerfile): node scripts/page-headers.ts > page-headers.caddy
import { PAGE_POLICY, caddyHeaderLines } from "../pagePolicy.ts";

process.stdout.write(caddyHeaderLines(PAGE_POLICY));
