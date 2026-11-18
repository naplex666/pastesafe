/**
 * PasteSafe — report storage.
 *
 * With Firebase: reports are stored in Firestore under the signed-in
 * user's own collection — REDACTED TEXT ONLY, never the original paste.
 * In demo mode (no Firebase config): localStorage, same shape, same rule.
 */

import {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDocs,
  limit,
  orderBy,
  query,
  serverTimestamp,
  type Timestamp,
} from 'firebase/firestore';
import { getFirebase } from './firebase';
import type { RedactionFinding } from './redact';
import type { TriageResult } from './hybrid';

export interface SavedReport {
  id: string;
  createdAt: number;
  redactedText: string;
  findings: RedactionFinding[];
  triage: TriageResult | null;
  mode: string;
}

const LOCAL_KEY = 'pastesafe.reports.v1';

function localList(): SavedReport[] {
  try {
    const raw = localStorage.getItem(LOCAL_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedReport[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function localSave(reports: SavedReport[]): void {
  try {
    localStorage.setItem(LOCAL_KEY, JSON.stringify(reports.slice(0, 50)));
  } catch {
    // Storage full or unavailable — history is best-effort in demo mode.
  }
}

export async function saveReport(
  uid: string | null,
  report: Omit<SavedReport, 'id' | 'createdAt'>,
): Promise<SavedReport> {
  const fb = getFirebase();
  const createdAt = Date.now();
  if (!fb || !uid) {
    const saved: SavedReport = {
      ...report,
      id: `local-${createdAt}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt,
    };
    localSave([saved, ...localList()]);
    return saved;
  }
  const ref = await addDoc(collection(fb.db, 'users', uid, 'reports'), {
    ...report,
    createdAt: serverTimestamp(),
  });
  return { ...report, id: ref.id, createdAt };
}

export async function listReports(uid: string | null): Promise<SavedReport[]> {
  const fb = getFirebase();
  if (!fb || !uid) return localList();
  try {
    const snap = await getDocs(
      query(
        collection(fb.db, 'users', uid, 'reports'),
        orderBy('createdAt', 'desc'),
        limit(20),
      ),
    );
    return snap.docs.map((d) => {
      const data = d.data() as Omit<SavedReport, 'id' | 'createdAt'> & {
        createdAt?: Timestamp | number;
      };
      const ts = data.createdAt;
      return {
        ...data,
        id: d.id,
        createdAt:
          typeof ts === 'number'
            ? ts
            : ts?.toMillis?.() ?? Date.now(),
      } as SavedReport;
    });
  } catch {
    return localList();
  }
}

export async function deleteReport(uid: string | null, id: string): Promise<void> {
  const fb = getFirebase();
  if (!fb || !uid || id.startsWith('local-')) {
    localSave(localList().filter((r) => r.id !== id));
    return;
  }
  await deleteDoc(doc(fb.db, 'users', uid, 'reports', id));
}
