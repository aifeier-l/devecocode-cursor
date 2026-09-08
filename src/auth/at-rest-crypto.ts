import { createDecipheriv, createCipheriv, randomBytes, type CipherGCM, type DecipherGCM } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { getKeyDirPath, getTokenDekPath } from "./host-paths.js";
import { isCursorOAuthCredential, type CursorOAuthCredential } from "./credential-manager.js";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const KEK_LENGTH = 32;
const DEK_LENGTH = 32;

const SENSITIVE_AUTH_KEYS = new Set(["access", "refresh", "key", "token"]);

export interface EncryptedBlob {
  version: number;
  algorithm: "aes-256-gcm";
  ciphertext: string;
  iv: string;
  authTag: string;
  timeStamp: number;
}

interface WrappedDekData {
  version: number;
  algorithm: "aes-256-gcm";
  kekId: string;
  encryptedDek: string;
  iv: string;
  authTag: string;
  timeStamp: number;
}

function loadKey(kekId: string): Buffer | undefined {
  const path = join(getKeyDirPath(), `${kekId}.bin`);
  if (!existsSync(path)) return undefined;
  return readFileSync(path);
}

function loadDek(): Buffer | undefined {
  const path = getTokenDekPath();
  if (!existsSync(path)) return undefined;
  const wrapped = JSON.parse(readFileSync(path, "utf8")) as WrappedDekData;
  const kek = loadKey(wrapped.kekId);
  if (!kek || kek.length !== KEK_LENGTH) return undefined;
  const iv = Buffer.from(wrapped.iv, "base64");
  const authTag = Buffer.from(wrapped.authTag, "base64");
  const encryptedDek = Buffer.from(wrapped.encryptedDek, "base64");
  const decipher = createDecipheriv(ALGORITHM, kek, iv) as DecipherGCM;
  decipher.setAuthTag(authTag);
  const dek = Buffer.concat([decipher.update(encryptedDek), decipher.final()]);
  return dek.length === DEK_LENGTH ? dek : undefined;
}

export function isEncryptedBlob(value: unknown): value is EncryptedBlob {
  if (!value || typeof value !== "object") return false;
  const c = value as Partial<EncryptedBlob>;
  return (
    c.algorithm === ALGORITHM &&
    typeof c.version === "number" &&
    typeof c.ciphertext === "string" &&
    typeof c.iv === "string" &&
    typeof c.authTag === "string" &&
    typeof c.timeStamp === "number"
  );
}

export function decryptForLocalStorage(blob: EncryptedBlob): string {
  const dek = loadDek();
  if (!dek) throw new Error("Unable to load local data-encryption key");
  const iv = Buffer.from(blob.iv, "base64");
  const authTag = Buffer.from(blob.authTag, "base64");
  const ciphertext = Buffer.from(blob.ciphertext, "base64");
  const decipher = createDecipheriv(ALGORITHM, dek, iv) as DecipherGCM;
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

export function encryptForLocalStorage(plaintext: string): EncryptedBlob {
  const dek = loadDek();
  if (!dek) throw new Error("Unable to load local data-encryption key");
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, dek, iv) as CipherGCM;
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: 1,
    algorithm: ALGORITHM,
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    timeStamp: Date.now(),
  };
}

/**
 * Decrypt the `access`/`refresh` fields of a stored provider record. OpenCode
 * stores plain strings; DevEco Code stores AES-256-GCM blobs. This handles both.
 */
export function unwrapCursorAuth(record: unknown): CursorOAuthCredential | undefined {
  if (!record || typeof record !== "object") return undefined;
  const rec = record as Record<string, unknown>;
  if (rec.type !== "oauth") return undefined;

  const refresh = decryptIfNeeded(rec.refresh);
  if (!refresh) return undefined;
  const access = decryptIfNeeded(rec.access);
  const expires = typeof rec.expires === "number" ? rec.expires : 0;

  const cred: CursorOAuthCredential = {
    type: "oauth",
    refresh,
    expires,
    ...(typeof access === "string" ? { access } : {}),
  };
  return isCursorOAuthCredential(cred) ? cred : undefined;
}

function decryptIfNeeded(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (isEncryptedBlob(value)) {
    try {
      return decryptForLocalStorage(value);
    } catch {
      return undefined;
    }
  }
  return undefined;
}
