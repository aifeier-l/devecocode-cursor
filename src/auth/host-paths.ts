import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Resolve the host app directory used by OpenCode / DevEco Code.
 *
 * OpenCode stores credentials under `$XDG_DATA_HOME/opencode` (or
 * `~/.local/share/opencode`); DevEco Code reuses the same layout but names the
 * directory `deveco` (set by the winsw service's `XDG_CONFIG_HOME` /
 * `XDG_DATA_HOME`). Detect which host is running by looking for DevEco-only
 * markers, falling back to the standard `opencode` name.
 */
function resolveAppName(): "deveco" | "opencode" {
  const configBase = getConfigBase();
  if (process.env.DEVECO_SERVER_PASSWORD) return "deveco";
  if (existsSync(join(configBase, "deveco", "token.dek"))) return "deveco";
  return "opencode";
}

function getDataBase(): string {
  return process.env.XDG_DATA_HOME || join(homedir(), ".local", "share");
}

function getConfigBase(): string {
  return process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
}

export function resolveHostDataDir(): string {
  return join(getDataBase(), resolveAppName());
}

export function resolveHostConfigDir(): string {
  return join(getConfigBase(), resolveAppName());
}

export function getAuthJsonPath(): string {
  return join(resolveHostDataDir(), "auth.json");
}

export function getTokenDekPath(): string {
  return join(resolveHostConfigDir(), "token.dek");
}

export function getKeyDirPath(): string {
  return join(resolveHostConfigDir(), "keys");
}
