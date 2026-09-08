/**
 * Atomic read/write access to the host auth.json Cursor entry.
 * Single implementation used by plugin config, browser login, and token refresh.
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { CURSOR_PROVIDER_ID } from "../shared/constants.js";
import { log } from "../shared/log.js";
import { getAuthJsonPath } from "./host-paths.js";
import { unwrapCursorAuth } from "./at-rest-crypto.js";
import type { CursorOAuthCredential } from "./credential-manager.js";

/**
 * Best-effort read of the stored Cursor OAuth entry.
 *
 * In plain OpenCode the `access`/`refresh` fields are strings. In DevEco Code
 * they are AES-256-GCM blobs (see security/local-crypto), so this unwraps them
 * with the same key chain before validating. Returns undefined when missing or
 * malformed. Expired access tokens are still returned when a refresh token is
 * present so callers can refresh.
 */
export function readStoredCursorAuth(): CursorOAuthCredential | undefined {
  try {
    const data = JSON.parse(readFileSync(getAuthJsonPath(), "utf8"));
    return unwrapCursorAuth(data?.[CURSOR_PROVIDER_ID]);
  } catch {
    return undefined;
  }
}

/**
 * Persist Cursor credentials into the host auth.json.
 *
 * In DevEco Code the auth.json is encrypted at rest by the host's Auth service,
 * so writing plaintext here would corrupt it. Prefer persisting via
 * `input.client.auth.set` (the host re-encrypts). This disk fallback is kept
 * for plain OpenCode only and is a best-effort no-op when the file is
 * encrypted/read in plain OpenCode format only.
 */
export function writeStoredCursorAuth(auth: CursorOAuthCredential): void {
  try {
    const authPath = getAuthJsonPath();
    mkdirSync(dirname(authPath), { recursive: true });

    let data: Record<string, unknown> = {};
    if (existsSync(authPath)) {
      try {
        data = JSON.parse(readFileSync(authPath, "utf8")) as Record<
          string,
          unknown
        >;
      } catch {
        // Keep empty object only when the file is unreadable JSON.
        data = {};
      }
    }

    data[CURSOR_PROVIDER_ID] = {
      type: "oauth",
      access: auth.access,
      refresh: auth.refresh,
      expires: auth.expires,
    };

    const tmpPath = `${authPath}.${process.pid}.${Date.now()}.tmp`;
    writeFileSync(tmpPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
    renameSync(tmpPath, authPath);
  } catch (err) {
    const summary = err instanceof Error ? err.message : String(err);
    log.warn(
      `[opencode-cursor] failed to persist refreshed Cursor auth: ${summary}`,
    );
  }
}
