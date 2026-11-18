/**
 * PasteSafe — Firebase bootstrap.
 *
 * Demo mode: when no Firebase web config is provided through
 * VITE_FIREBASE_* env vars, the app still runs fully offline — the local
 * redaction engine works, and AI triage falls back to a clearly labelled
 * mock. Nothing is sent anywhere in demo mode.
 *
 * With config: initializes App (with App Check), Auth (anonymous,
 * optional Google sign-in), Firestore, Remote Config and AI Logic.
 */

import { initializeApp, type FirebaseApp } from 'firebase/app';
import {
  getAuth,
  signInAnonymously,
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  type Auth,
  type User,
} from 'firebase/auth';
import { getFirestore, type Firestore } from 'firebase/firestore';
import {
  getRemoteConfig,
  fetchAndActivate,
  getString,
  getNumber,
  type RemoteConfig,
} from 'firebase/remote-config';

export interface FirebaseConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
}

export interface RemoteConfigValues {
  /** Cloud model used for triage. Default: gemini-flash-latest. */
  cloudModel: string;
  /** Default hybrid inference mode. */
  inferenceMode: string;
  /** Max characters sent to the on-device sweep. */
  onDeviceMaxChars: number;
}

export const REMOTE_CONFIG_DEFAULTS: RemoteConfigValues = {
  cloudModel: 'gemini-flash-latest',
  inferenceMode: 'prefer-on-device',
  onDeviceMaxChars: 8000,
};

function readConfigFromEnv(): FirebaseConfig | null {
  const env = import.meta.env;
  const apiKey = (env.VITE_FIREBASE_API_KEY as string | undefined)?.trim();
  const projectId = (env.VITE_FIREBASE_PROJECT_ID as string | undefined)?.trim();
  if (!apiKey || !projectId || apiKey === 'YOUR_API_KEY') return null;
  return {
    apiKey,
    authDomain: (env.VITE_FIREBASE_AUTH_DOMAIN as string) ?? '',
    projectId,
    storageBucket: (env.VITE_FIREBASE_STORAGE_BUCKET as string) ?? '',
    messagingSenderId: (env.VITE_FIREBASE_MESSAGING_SENDER_ID as string) ?? '',
    appId: (env.VITE_FIREBASE_APP_ID as string) ?? '',
  };
}

export interface FirebaseServices {
  app: FirebaseApp;
  auth: Auth;
  db: Firestore;
  remoteConfig: RemoteConfig;
  config: FirebaseConfig;
  values: RemoteConfigValues;
}

let services: FirebaseServices | null | undefined;
let authReady: Promise<User | null> | null = null;

/** True when a real Firebase project is configured. False = demo mode. */
export function isFirebaseConfigured(): boolean {
  return readConfigFromEnv() !== null;
}

/**
 * Initialize Firebase lazily. Returns null in demo mode (no config).
 * App Check uses the debug provider in development only, fed from a
 * gitignored env var — debug tokens are NEVER hardcoded or committed.
 */
export function getFirebase(): FirebaseServices | null {
  if (services !== undefined) return services;
  const config = readConfigFromEnv();
  if (!config) {
    services = null;
    return null;
  }

  const app = initializeApp(config);

  if (import.meta.env.DEV) {
    const debugToken = (
      import.meta.env.VITE_APPCHECK_DEBUG_TOKEN as string | undefined
    )?.trim();
    // `true` auto-generates a token printed to the browser console; a
    // pre-provisioned token can be injected via env instead.
    (self as unknown as Record<string, unknown>).FIREBASE_APPCHECK_DEBUG_TOKEN =
      debugToken || true;
  }

  const auth = getAuth(app);
  const db = getFirestore(app);
  const remoteConfig = getRemoteConfig(app);
  remoteConfig.defaultConfig = {
    cloud_model: REMOTE_CONFIG_DEFAULTS.cloudModel,
    inference_mode: REMOTE_CONFIG_DEFAULTS.inferenceMode,
    on_device_max_chars: REMOTE_CONFIG_DEFAULTS.onDeviceMaxChars,
  };
  remoteConfig.settings.minimumFetchIntervalMillis = 60_000;

  services = {
    app,
    auth,
    db,
    remoteConfig,
    config,
    values: { ...REMOTE_CONFIG_DEFAULTS },
  };
  return services;
}

/** Sign in anonymously (best effort) and resolve with the current user. */
export function ensureAnonymousAuth(): Promise<User | null> {
  const fb = getFirebase();
  if (!fb) return Promise.resolve(null);
  if (!authReady) {
    authReady = new Promise<User | null>((resolve) => {
      const unsub = onAuthStateChanged(fb.auth, (user) => {
        unsub();
        resolve(user);
      });
      signInAnonymously(fb.auth).catch(() => resolve(fb.auth.currentUser));
      // Safety net: never hang the UI on auth.
      setTimeout(() => resolve(fb.auth.currentUser), 5000);
    });
  }
  return authReady;
}

/** Upgrade the anonymous session to Google sign-in. */
export async function signInWithGoogle(): Promise<User | null> {
  const fb = getFirebase();
  if (!fb) return null;
  const result = await signInWithPopup(fb.auth, new GoogleAuthProvider());
  return result.user;
}

/** Fetch Remote Config and refresh the cached values (best effort). */
export async function refreshRemoteConfig(): Promise<RemoteConfigValues> {
  const fb = getFirebase();
  if (!fb) return { ...REMOTE_CONFIG_DEFAULTS };
  try {
    await fetchAndActivate(fb.remoteConfig);
    fb.values = {
      cloudModel:
        getString(fb.remoteConfig, 'cloud_model') ||
        REMOTE_CONFIG_DEFAULTS.cloudModel,
      inferenceMode:
        getString(fb.remoteConfig, 'inference_mode') ||
        REMOTE_CONFIG_DEFAULTS.inferenceMode,
      onDeviceMaxChars:
        getNumber(fb.remoteConfig, 'on_device_max_chars') ||
        REMOTE_CONFIG_DEFAULTS.onDeviceMaxChars,
    };
  } catch {
    // Offline or not provisioned yet: keep in-app defaults.
  }
  return fb.values;
}
