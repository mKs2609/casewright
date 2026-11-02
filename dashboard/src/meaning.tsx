import {
  Ban,
  Check,
  CircleAlert,
  CircleCheck,
  Clock,
  LogIn,
  Mail,
  OctagonX,
  Phone,
  Search,
  TriangleAlert,
  UserRoundCheck,
  type LucideIcon,
} from "lucide-react";

export type Tone = "benign" | "suspicious" | "malicious" | "accent" | "muted";

export interface Meaning {
  word: string;
  tone: Tone;
  Icon: LucideIcon;
}

// Never colour alone: every state has a colour, an icon and a word.
const VERDICTS: Record<string, Meaning> = {
  benign: { word: "Safe", tone: "benign", Icon: Check },
  suspicious: { word: "Suspicious", tone: "suspicious", Icon: TriangleAlert },
  malicious: { word: "Attack", tone: "malicious", Icon: OctagonX },
};

const STATUSES: Record<string, Meaning> = {
  queued: { word: "Queued", tone: "muted", Icon: Clock },
  investigating: { word: "Investigating", tone: "accent", Icon: Search },
  awaiting_approval: { word: "Waiting for approval", tone: "suspicious", Icon: UserRoundCheck },
  needs_review: { word: "Needs review", tone: "suspicious", Icon: CircleAlert },
  closed: { word: "Closed", tone: "benign", Icon: CircleCheck },
  error: { word: "Failed", tone: "malicious", Icon: OctagonX },
};

const ACTION_STATUSES: Record<string, Meaning> = {
  pending: { word: "Waiting", tone: "suspicious", Icon: UserRoundCheck },
  executed: { word: "Done (simulated)", tone: "benign", Icon: Check },
  rejected: { word: "Rejected", tone: "muted", Icon: Ban },
  expired: { word: "Expired", tone: "muted", Icon: Clock },
};

const UNKNOWN: Meaning = { word: "Unknown", tone: "muted", Icon: CircleAlert };

export const verdictMeaning = (verdict: string): Meaning => VERDICTS[verdict] ?? UNKNOWN;
export const statusMeaning = (status: string): Meaning => STATUSES[status] ?? UNKNOWN;
export const actionStatusMeaning = (status: string): Meaning => ACTION_STATUSES[status] ?? UNKNOWN;

export const KIND_ICONS: Record<string, LucideIcon> = { email: Mail, call_transcript: Phone, login: LogIn };
export const KIND_WORDS: Record<string, string> = { email: "Email", call_transcript: "Phone call", login: "Sign-ins" };

/** Buttons say what happens: "Approve block", not "OK". */
export const ACTION_WORDS: Record<string, { name: string; approve: string }> = {
  monitor: { name: "Watch the account", approve: "Approve watching" },
  notify_user: { name: "Tell the person", approve: "Approve telling them" },
  force_password_reset: { name: "Force a password reset", approve: "Approve reset" },
  lock_account: { name: "Lock the account", approve: "Approve lock" },
  block_ip: { name: "Block this address", approve: "Approve block" },
  quarantine_email: { name: "Quarantine this sender's email", approve: "Approve quarantine" },
  block_sender_domain: { name: "Block this domain", approve: "Approve block" },
  block_phone_number: { name: "Block this number", approve: "Approve block" },
};

export const riskBand = (score: number): Tone => (score >= 65 ? "malicious" : score >= 30 ? "suspicious" : "benign");

export const when = (iso: string): string => new Date(iso).toLocaleString();
