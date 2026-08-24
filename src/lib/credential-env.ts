import { createHash } from "crypto";

/**
 * Credential environment variables read by the built-in provider auth
 * resolvers (mirrors the per-provider `envVars` lists in `*-auth.ts` /
 * `*-config.ts`). The quota-state cache fingerprints the VALUES of these
 * variables so concurrent opencode instances that use different accounts for
 * the same provider no longer share one per-user disk cache entry.
 */
export const CREDENTIAL_ENV_VARS = [
  "ALIBABA_API_KEY",
  "ALIBABA_CODING_PLAN_API_KEY",
  "CHUTES_API_KEY",
  "DEEPSEEK_API_KEY",
  "KILO_API_KEY",
  "KIMI_API_KEY",
  "KIMI_CODE_API_KEY",
  "MINIMAX_API_KEY",
  "MINIMAX_CHINA_CODING_PLAN_API_KEY",
  "MINIMAX_CODING_PLAN_API_KEY",
  "NANO_GPT_API_KEY",
  "NANOGPT_API_KEY",
  "OLLAMA_API_KEY",
  "OPENCODE_API_KEY",
  "SYNTHETIC_API_KEY",
  "ZAI_API_KEY",
  "ZAI_CODING_PLAN_API_KEY",
  "ZHIPU_API_KEY",
  "ZHIPU_CODING_PLAN_API_KEY",
] as const;

export type CredentialEnvSource = Record<string, string | undefined>;

const CREDENTIAL_FINGERPRINT_HEX_LENGTH = 12;

function fingerprint(pairs: string[]): string {
  return createHash("sha1")
    .update(pairs.join("\n"))
    .digest("hex")
    .slice(0, CREDENTIAL_FINGERPRINT_HEX_LENGTH);
}

/**
 * Stable, irreversible fingerprint of the credential env vars that are
 * currently set. Returns "" when none of the allowlisted variables carry a
 * value, so single-account setups keep byte-identical legacy cache keys (no
 * gratuitous cache misses across upgrades).
 *
 * Only a truncated one-way hash ever enters a cache key; raw credential
 * values are never embedded.
 */
export function buildCredentialEnvFingerprint(env: CredentialEnvSource = process.env): string {
  const pairs: string[] = [];
  for (const name of CREDENTIAL_ENV_VARS) {
    const value = env[name];
    if (value !== undefined && value !== "") {
      pairs.push(`${name}=${value}`);
    }
  }
  if (pairs.length === 0) {
    return "";
  }
  return fingerprint(pairs);
}

/**
 * Same fingerprint treatment for custom quota-provider definitions: each
 * definition declares its credential through an `apiKeyEnv` NAME (already part
 * of the cache identity). Two accounts that reuse the same variable NAME with
 * different VALUES still need distinct cache entries, so the declared
 * variables' values are fingerprinted as well. Definitions without an
 * `apiKeyEnv`, or whose variable is unset, contribute nothing.
 */
export function buildCustomApiKeyEnvFingerprint(
  apiKeyEnvNames: readonly (string | undefined)[],
  env: CredentialEnvSource = process.env,
): string {
  const pairs: string[] = [];
  for (const name of apiKeyEnvNames) {
    if (typeof name !== "string" || name === "") {
      continue;
    }
    const value = env[name];
    if (value !== undefined && value !== "") {
      pairs.push(`${name}=${value}`);
    }
  }
  if (pairs.length === 0) {
    return "";
  }
  return fingerprint(pairs);
}
