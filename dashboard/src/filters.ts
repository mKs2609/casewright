import type { IncidentSummary } from "./types";

/**
 * The Overview's filters: which incidents (all, attacks, those waiting for a decision) of which type.
 * They live in the address (#/?show=attacks&kind=email), so a reload or the Back button keeps them.
 * The address is read strictly: anything that is not one of these exact words means "all".
 */
export type Show = "all" | "attacks" | "waiting";
export type KindChoice = "all" | "email" | "sign-ins" | "calls";

export interface Filters {
  show: Show;
  kind: KindChoice;
}

export const NO_FILTERS: Filters = { show: "all", kind: "all" };

const SHOWS: readonly Show[] = ["all", "attacks", "waiting"];

/** The address's word for each type, and the incident kind it stands for. */
const KIND_CHOICES: Record<Exclude<KindChoice, "all">, string> = {
  email: "email",
  "sign-ins": "login",
  calls: "call_transcript",
};

const isKindChoice = (word: string | null): word is Exclude<KindChoice, "all"> =>
  word !== null && Object.hasOwn(KIND_CHOICES, word);

/** The filters in an address's query ("show=attacks&kind=email"). */
export function filtersFrom(query: string): Filters {
  const params = new URLSearchParams(query);
  const show = params.get("show");
  const kind = params.get("kind");
  return {
    show: SHOWS.find((word) => word === show) ?? "all",
    kind: isKindChoice(kind) ? kind : "all",
  };
}

/** The Overview's address for these filters: plain "#/" when nothing is filtered. */
export function addressFor(filters: Filters): string {
  const params = new URLSearchParams();
  if (filters.show !== "all") {
    params.set("show", filters.show);
  }
  if (filters.kind !== "all") {
    params.set("kind", filters.kind);
  }
  const query = params.toString();
  return query ? `#/?${query}` : "#/";
}

export const isAttack = (incident: IncidentSummary) => incident.verdict === "malicious";
export const isWaiting = (incident: IncidentSummary) => incident.status === "awaiting_approval";

export const ofKind = (kind: KindChoice) => (incident: IncidentSummary) =>
  kind === "all" || incident.kind === KIND_CHOICES[kind];

export const shown = (show: Show) => (incident: IncidentSummary) =>
  show === "all" || (show === "attacks" ? isAttack(incident) : isWaiting(incident));
