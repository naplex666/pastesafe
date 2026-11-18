/**
 * PasteSafe — deterministic, fully local secret & PII scanner.
 *
 * Runs 100% on-device (plain regex + Luhn check). No network, no cost.
 * This is the first privacy gate: it runs BEFORE anything is sent to any
 * AI model. Every finding is replaced with a [REDACTED:TYPE-N] placeholder.
 */

export type FindingSeverity = 'critical' | 'high' | 'medium';

export interface RedactionFinding {
  id: string;
  type: string;
  label: string;
  severity: FindingSeverity;
  /** Byte offset of the redacted span in the ORIGINAL text. */
  start: number;
  end: number;
  /** Masked preview, e.g. "AKIA…LE" — never the full value. */
  masked: string;
  /** The placeholder inserted into the redacted text. */
  placeholder: string;
}

export interface RedactionResult {
  originalText: string;
  redactedText: string;
  findings: RedactionFinding[];
  redactedCount: number;
  durationMs: number;
}

interface PatternDef {
  type: string;
  label: string;
  severity: FindingSeverity;
  /** Regex WITHOUT flags; the scanner adds "gd". */
  regex: RegExp;
  /** Capture-group indexes to redact (default: the whole match). */
  redactGroups?: number[];
  /** Optional extra validation; a candidate is dropped when it returns false. */
  validate?: (value: string) => boolean;
}

/** Luhn checksum — used to tell a real card number from a 16-digit ID. */
export function luhnCheck(digits: string): boolean {
  const clean = digits.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(clean)) return false;
  let sum = 0;
  let doubleUp = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = clean.charCodeAt(i) - 48;
    if (doubleUp) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleUp = !doubleUp;
  }
  return sum % 10 === 0;
}

const PATTERNS: PatternDef[] = [
  {
    type: 'pem-private-key',
    label: 'Private key (PEM)',
    severity: 'critical',
    regex:
      /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/,
  },
  {
    type: 'aws-access-key',
    label: 'AWS access key ID',
    severity: 'critical',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    type: 'aws-secret-key',
    label: 'AWS secret access key',
    severity: 'critical',
    regex:
      /(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    redactGroups: [2],
  },
  {
    type: 'github-token',
    label: 'GitHub token',
    severity: 'critical',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|ghx)_[A-Za-z0-9]{36,}\b/,
  },
  {
    type: 'github-fine-grained-token',
    label: 'GitHub fine-grained token',
    severity: 'critical',
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
  },
  {
    type: 'stripe-secret-key',
    label: 'Stripe secret key',
    severity: 'critical',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  },
  {
    type: 'slack-token',
    label: 'Slack token',
    severity: 'critical',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  {
    type: 'jwt',
    label: 'JWT (JSON Web Token)',
    severity: 'high',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    type: 'bearer-token',
    label: 'Bearer token',
    severity: 'high',
    regex: /Bearer\s+([A-Za-z0-9\-._~+/=]{20,})/i,
    redactGroups: [1],
  },
  {
    type: 'generic-secret',
    label: 'API key / token / secret',
    severity: 'high',
    regex:
      /\b(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=]{16,})['"]?/i,
    redactGroups: [2],
  },
  {
    type: 'password',
    label: 'Password',
    severity: 'high',
    regex: /\b(pass(?:word|wd)?|pwd)\b\s*[:=]\s*['"]?([^\s'"]{4,})['"]?/i,
    redactGroups: [2],
  },
  {
    type: 'url-credentials',
    label: 'Credentials embedded in URL',
    severity: 'high',
    regex: /(https?:\/\/)([^:/\s]+):([^@/\s]+)@/i,
    redactGroups: [2, 3],
  },
  {
    type: 'email',
    label: 'Email address',
    severity: 'medium',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  },
  {
    type: 'phone-id',
    label: 'Indonesian phone number',
    severity: 'medium',
    regex: /\b(?:\+62|62|0)8\d{7,12}\b/,
  },
  {
    type: 'credit-card',
    label: 'Credit card number',
    severity: 'high',
    regex: /\b(?:\d[ -]?){13,19}\b/,
    validate: (v) => luhnCheck(v),
  },
  {
    type: 'national-id',
    label: 'Possible national ID (16 digits)',
    severity: 'medium',
    regex: /\b\d{16}\b/,
    validate: (v) => !luhnCheck(v),
  },
];

function maskValue(value: string): string {
  const clean = value.replace(/\s+/g, ' ');
  if (clean.length <= 4) return '••••';
  if (clean.length <= 10) return `${clean.slice(0, 2)}••••${clean.slice(-2)}`;
  return `${clean.slice(0, 4)}…${clean.slice(-2)}`;
}

interface Span {
  start: number;
  end: number;
  type: string;
  label: string;
  severity: FindingSeverity;
  value: string;
}

export function redactText(originalText: string): RedactionResult {
  const startedAt = performance.now();
  const spans: Span[] = [];

  for (const def of PATTERNS) {
    // "g" for matchAll, "d" for match indices (ES2022).
    const flags = def.regex.flags.includes('i') ? 'gid' : 'gd';
    const re = new RegExp(def.regex.source, flags);
    for (const match of originalText.matchAll(re)) {
      const groups = def.redactGroups ?? [0];
      for (const group of groups) {
        const indices = match.indices?.[group];
        if (!indices) continue;
        const [start, end] = indices;
        const value = match[group] ?? '';
        if (!value || end <= start) continue;
        if (def.validate && !def.validate(value)) continue;
        spans.push({
          start,
          end,
          type: def.type,
          label: def.label,
          severity: def.severity,
          value,
        });
      }
    }
  }

  // Longest span first at the same start; then drop anything overlapping
  // a span that was already accepted (earlier patterns win ties).
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const accepted: Span[] = [];
  for (const span of spans) {
    const overlaps = accepted.some(
      (s) => span.start < s.end && span.end > s.start,
    );
    if (!overlaps) accepted.push(span);
  }
  accepted.sort((a, b) => a.start - b.start);

  const counters = new Map<string, number>();
  const findings: RedactionFinding[] = accepted.map((span) => {
    const n = (counters.get(span.type) ?? 0) + 1;
    counters.set(span.type, n);
    const placeholder = `[REDACTED:${span.type.toUpperCase()}-${n}]`;
    return {
      id: `${span.type}-${n}`,
      type: span.type,
      label: span.label,
      severity: span.severity,
      start: span.start,
      end: span.end,
      masked: maskValue(span.value),
      placeholder,
    };
  });

  // Rebuild the redacted text from the end so offsets stay valid.
  let redactedText = originalText;
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i];
    redactedText =
      redactedText.slice(0, f.start) + f.placeholder + redactedText.slice(f.end);
  }

  return {
    originalText,
    redactedText,
    findings,
    redactedCount: findings.length,
    durationMs: performance.now() - startedAt,
  };
}
