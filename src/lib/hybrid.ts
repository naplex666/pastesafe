/**
 * PasteSafe — Firebase AI Logic hybrid wrapper.
 *
 * Two stages, two engines:
 *  1. Semantic sweep (on-device first): runs on the ORIGINAL pasted text
 *     while it is still on the device — a privacy scan + short summary.
 *     Uses the Firebase AI Logic hybrid model (Gemini Nano when available,
 *     cloud fallback). The SDK reports where the response actually ran
 *     (`response.inferenceSource`), and that is what the UI badge shows.
 *  2. Cloud triage: runs ONLY on redacted text, ONLY after the user
 *     reviews and approves it. Full severity + CVSS draft + remediation.
 *
 * Demo mode (no Firebase config): both stages return clearly labelled
 * mock results derived from the local deterministic scan — never fake AI.
 */

import {
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  InferenceSource,
} from 'firebase/ai';
import { getFirebase, type RemoteConfigValues } from './firebase';

export type HybridMode =
  | 'prefer-on-device'
  | 'only-on-device'
  | 'prefer-in-cloud'
  | 'only-in-cloud';

export type EngineKind = 'on-device' | 'cloud' | 'local' | 'mock';

export interface EngineBadge {
  engine: EngineKind;
  /** e.g. "Gemini Nano 4", "gemini-3.5-flash-lite", "Local regex", "Mock". */
  model: string;
  latencyMs: number;
  /** "$0 · offline" for on-device, "~free tier" for cloud, "—" for local. */
  cost: string;
  /** Human-readable note, e.g. why the cloud was used. */
  note?: string;
}

export interface SweepFinding {
  type: string;
  excerpt: string;
  confidence: number;
}

export interface SweepResult {
  findings: SweepFinding[];
  summary: string;
  riskLevel: 'low' | 'medium' | 'high';
  badge: EngineBadge;
}

export interface TriageResult {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvssVector: string;
  cvssScore: number;
  category: string;
  summary: string;
  remediation: string[];
  badge: EngineBadge;
}

export interface RequestLogEntry {
  id: string;
  at: string;
  step: string;
  engine: EngineKind;
  /** Bytes that actually left the device (0 before redaction). */
  bytesSent: number;
  detail: string;
}

const MODE_MAP: Record<HybridMode, InferenceMode> = {
  'prefer-on-device': InferenceMode.PREFER_ON_DEVICE,
  'only-on-device': InferenceMode.ONLY_ON_DEVICE,
  'prefer-in-cloud': InferenceMode.PREFER_IN_CLOUD,
  'only-in-cloud': InferenceMode.ONLY_IN_CLOUD,
};

let nanoAvailability: 'available' | 'unavailable' | 'unknown' = 'unknown';

/** Probe the Chrome Prompt API for on-device Gemini Nano availability. */
export async function detectNanoAvailability(): Promise<
  'available' | 'unavailable' | 'unknown'
> {
  if (nanoAvailability !== 'unknown') return nanoAvailability;
  try {
    const w = window as unknown as Record<string, unknown>;
    const LM = w.LanguageModel as
      | { availability?: () => Promise<string> }
      | undefined;
    if (LM?.availability) {
      const state = await LM.availability();
      nanoAvailability = state === 'available' ? 'available' : 'unavailable';
      return nanoAvailability;
    }
    const ai = w.ai as
      | { languageModel?: { capabilities?: () => Promise<{ available?: string }> } }
      | undefined;
    if (ai?.languageModel?.capabilities) {
      const caps = await ai.languageModel.capabilities();
      nanoAvailability =
        caps.available === 'readily' ? 'available' : 'unavailable';
      return nanoAvailability;
    }
  } catch {
    // Prompt API not present in this browser.
  }
  nanoAvailability = 'unknown';
  return nanoAvailability;
}

/** Extract the first JSON object from model output (tolerant parser). */
function parseJsonObject<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(text.slice(start, end + 1)) as T;
      } catch {
        return null;
      }
    }
    return null;
  }
}

interface SweepJson {
  findings?: Array<{ type?: string; excerpt?: string; confidence?: number }>;
  summary?: string;
  riskLevel?: string;
}

/** Stage 1 — semantic privacy sweep. Runs on the ORIGINAL text, on-device first. */
export async function semanticSweep(
  originalText: string,
  redactedCount: number,
  mode: HybridMode,
  values: RemoteConfigValues,
): Promise<SweepResult> {
  const startedAt = performance.now();
  const fb = getFirebase();

  // Demo mode: honest mock built from the deterministic scan, labelled as such.
  if (!fb) {
    return {
      findings: [],
      summary:
        redactedCount > 0
          ? `Demo mode: the deterministic scan already found ${redactedCount} secret(s). Connect Firebase to run the on-device semantic sweep with Gemini Nano.`
          : 'Demo mode: nothing sensitive detected by the deterministic scan. Connect Firebase to run the on-device semantic sweep with Gemini Nano.',
      riskLevel: redactedCount > 0 ? 'high' : 'low',
      badge: {
        engine: 'mock',
        model: 'Mock sweep (demo mode)',
        latencyMs: Math.round(performance.now() - startedAt),
        cost: '$0',
        note: 'Firebase is not configured — no model ran. Connect Firebase for a real sweep.',
      },
    };
  }

  const ai = getAI(fb.app, {
    backend: new GoogleAIBackend(),
    useLimitedUseAppCheckTokens: true,
  });
  const model = getGenerativeModel(ai, {
    mode: MODE_MAP[mode],
    inCloudParams: {
      model: values.cloudModel,
      generationConfig: {
        responseMimeType: 'application/json',
        maxOutputTokens: 1024,
        temperature: 0.2,
      },
    },
  });

  const prompt = [
    'You are a privacy scanner running on the user\u2019s own device.',
    'Scan the text below for anything sensitive the user may have missed:',
    'names of people, emails, phone numbers, addresses, credentials, tokens,',
    'API keys, passwords, internal hostnames, or customer data.',
    'Return ONLY valid JSON, no markdown, no extra text:',
    '{"findings":[{"type":"email|phone|name|credential|internal-host|other","excerpt":"short quote (max 40 chars)","confidence":0.0-1.0}],"summary":"one sentence","riskLevel":"low|medium|high"}',
    'If nothing sensitive is found, return empty findings and riskLevel "low".',
    '',
    'TEXT TO SCAN:',
    originalText.slice(0, values.onDeviceMaxChars),
  ].join('\n');

  try {
    const result = await model.generateContent(prompt);
    const response = result.response;
    const source = response.inferenceSource;
    const latencyMs = Math.round(performance.now() - startedAt);
    const parsed = parseJsonObject<SweepJson>(response.text());
    const onDevice = source === InferenceSource.ON_DEVICE;
    return {
      findings: (parsed?.findings ?? []).map((f) => ({
        type: f.type ?? 'other',
        excerpt: f.excerpt ?? '',
        confidence: Math.min(1, Math.max(0, f.confidence ?? 0.5)),
      })),
      summary: parsed?.summary ?? 'Sweep completed.',
      riskLevel:
        parsed?.riskLevel === 'high' || parsed?.riskLevel === 'medium'
          ? parsed.riskLevel
          : 'low',
      badge: {
        engine: onDevice ? 'on-device' : 'cloud',
        model: onDevice ? 'Gemini Nano 4 (on-device)' : `${values.cloudModel} (cloud fallback)`,
        latencyMs,
        cost: onDevice ? '$0 · offline' : 'free tier',
        note: onDevice
          ? 'Ran on this device — text never left the browser.'
          : 'On-device model unavailable — the SDK fell back to the cloud for this step.',
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      mode === 'only-on-device'
        ? `On-device inference failed (Nano unavailable or not ready): ${message}`
        : `Semantic sweep failed: ${message}`,
    );
  }
}

interface TriageJson {
  title?: string;
  severity?: string;
  cvssVector?: string;
  cvssScore?: number;
  category?: string;
  summary?: string;
  remediation?: string[];
}

/** Stage 2 — full triage. Runs ONLY on redacted text, ONLY on user tap. */
export async function cloudTriage(
  redactedText: string,
  values: RemoteConfigValues,
): Promise<TriageResult> {
  const startedAt = performance.now();
  const fb = getFirebase();

  // Demo mode: keyword-based mock triage, clearly labelled — never fake AI.
  if (!fb) {
    const lower = redactedText.toLowerCase();
    const looksInjection = /sql injection|sqli|injection/i.test(lower);
    const looksXss = /xss|cross-site scripting/i.test(lower);
    const looksAuth = /auth|session|password|login|token/i.test(lower);
    const severity = looksInjection ? 'high' : looksXss ? 'medium' : looksAuth ? 'medium' : 'low';
    return {
      title: 'Demo triage (mock)',
      severity,
      cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
      cvssScore: severity === 'high' ? 7.5 : severity === 'medium' ? 5.0 : 2.0,
      category: looksInjection
        ? 'Injection'
        : looksXss
          ? 'Cross-Site Scripting (XSS)'
          : looksAuth
            ? 'Authentication & Session'
            : 'General finding',
      summary:
        'Demo mode: this is a keyword-based mock, not a model result. Connect Firebase to run the real cloud triage with Gemini.',
      remediation: [
        'Connect a Firebase project (see README) to enable real AI triage.',
        'Review the redacted text and confirm no secrets remain before sharing.',
      ],
      badge: {
        engine: 'mock',
        model: 'Mock triage (demo mode)',
        latencyMs: Math.round(performance.now() - startedAt),
        cost: '$0',
        note: 'Firebase is not configured — no model ran.',
      },
    };
  }

  const ai = getAI(fb.app, {
    backend: new GoogleAIBackend(),
    useLimitedUseAppCheckTokens: true,
  });
  const model = getGenerativeModel(ai, {
    model: values.cloudModel,
    generationConfig: {
      responseMimeType: 'application/json',
      maxOutputTokens: 2048,
      temperature: 0.3,
    },
  });

  const prompt = [
    'You are a senior application-security analyst triaging a bug bounty report.',
    'The report text below was already redacted on the user\u2019s device — secrets were replaced with [REDACTED:...] placeholders.',
    'Analyze it and return ONLY valid JSON, no markdown, no extra text:',
    '{"title":"short title","severity":"critical|high|medium|low|info","cvssVector":"CVSS:4.0 vector string","cvssScore":0.0-10.0,"category":"e.g. Injection, XSS, Authentication","summary":"2-3 sentences","remediation":["concrete step 1","concrete step 2"]}',
    'Be conservative: if the report is vague, use severity "low" or "info" and say so in the summary.',
    '',
    'REDACTED REPORT:',
    redactedText,
  ].join('\n');

  const result = await model.generateContent(prompt);
  const response = result.response;
  const latencyMs = Math.round(performance.now() - startedAt);
  const parsed = parseJsonObject<TriageJson>(response.text());
  if (!parsed) throw new Error('Cloud triage returned an unparseable response.');

  const severity =
    parsed.severity === 'critical' ||
    parsed.severity === 'high' ||
    parsed.severity === 'medium' ||
    parsed.severity === 'low' ||
    parsed.severity === 'info'
      ? parsed.severity
      : 'info';

  return {
    title: parsed.title ?? 'Untitled finding',
    severity,
    cvssVector:
      parsed.cvssVector ??
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    cvssScore:
      typeof parsed.cvssScore === 'number'
        ? Math.min(10, Math.max(0, parsed.cvssScore))
        : 0,
    category: parsed.category ?? 'General finding',
    summary: parsed.summary ?? '',
    remediation: parsed.remediation ?? [],
    badge: {
      engine: 'cloud',
      model: `${values.cloudModel} (cloud)`,
      latencyMs,
      cost: 'free tier',
      note: 'Ran on redacted text only — secrets never left the device.',
    },
  };
}
