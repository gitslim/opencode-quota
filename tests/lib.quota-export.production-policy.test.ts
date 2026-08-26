import { access, rm } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TEST_RUNTIME_ROOT = "/tmp/opencode-quota-export-production-policy-tests";
const UNCACHED_CANONICAL_PROVIDER_IDS = [
  "anthropic",
  "copilot",
  "cursor",
  "google-antigravity",
  "google-gemini-cli",
  "openrouter",
  "qwen-code",
  "xai",
] as const;

vi.mock("../src/lib/opencode-runtime-paths.js", () => ({
  getOpencodeRuntimeDirCandidates: () => ({
    dataDirs: [`${TEST_RUNTIME_ROOT}/data`],
    configDirs: [`${TEST_RUNTIME_ROOT}/config`],
    cacheDirs: [`${TEST_RUNTIME_ROOT}/cache`],
    stateDirs: [`${TEST_RUNTIME_ROOT}/state`],
  }),
  getOpencodeRuntimeDirs: () => ({
    dataDir: `${TEST_RUNTIME_ROOT}/data`,
    configDir: `${TEST_RUNTIME_ROOT}/config`,
    cacheDir: `${TEST_RUNTIME_ROOT}/cache`,
    stateDir: `${TEST_RUNTIME_ROOT}/state`,
  }),
}));

function createTestContext() {
  return {
    client: {
      config: {
        providers: async () => ({ data: { providers: [] } }),
        get: async () => ({ data: {} }),
      },
    },
    config: {
      googleModels: ["CLAUDE"],
      anthropicBinaryPath: "claude",
      cursorPlan: "none",
      onlyCurrentModel: false,
      showSessionTokens: false,
    },
  } as any;
}

describe("quota export production cache policy", () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    await rm(TEST_RUNTIME_ROOT, { recursive: true, force: true });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.resetModules();
    await rm(TEST_RUNTIME_ROOT, { recursive: true, force: true });
  });

  it("exports latest live snapshots for every canonical uncached provider without disk reuse", async () => {
    const { buildQuotaExport } = await import("../src/lib/quota-export.js");
    const { fetchQuotaProviderResult, __resetQuotaStateForTests } = await import(
      "../src/lib/quota-state.js"
    );
    const { getProviders } = await import("../src/providers/registry.js");
    __resetQuotaStateForTests();

    const providersById = new Map(getProviders().map((provider) => [provider.id, provider]));
    const providers = UNCACHED_CANONICAL_PROVIDER_IDS.map((id) => {
      const provider = providersById.get(id);
      if (!provider) throw new Error(`Missing production provider ${id}`);
      expect(provider.cachePolicy).toEqual({ kind: "uncached" });
      vi.spyOn(provider, "fetch").mockResolvedValue({
        attempted: true,
        entries: [
          {
            accounting: {
              resultType: "quota",
              acquisitionMethod: "remote_api",
              ownership: "maintained",
              authority: "provider_reported",
            },
            name: `Latest ${id}`,
            percentRemaining: 73,
          },
        ],
        errors: [],
      });
      return provider;
    });
    const ctx = createTestContext();

    for (const provider of providers) {
      await fetchQuotaProviderResult({ provider, ctx, ttlMs: 60_000 });
    }
    const exported = await buildQuotaExport({ providers, ctx, ttlMs: 60_000, fromCache: true });

    for (const id of UNCACHED_CANONICAL_PROVIDER_IDS) {
      expect(exported.providers[id]).toMatchObject({
        status: "ok",
        entries: [{ name: `Latest ${id}`, percentRemaining: 73 }],
      });
    }
    expect(exported.providers.cursor.status).toBe("ok");
    expect(exported.providers["qwen-code"].status).toBe("ok");
    await expect(access(`${TEST_RUNTIME_ROOT}/cache/quota-provider-state`)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("isolates process-local export snapshots by runtime client owner", async () => {
    const { buildQuotaExport } = await import("../src/lib/quota-export.js");
    const { fetchQuotaProviderResult, readCachedProviderResult, __resetQuotaStateForTests } =
      await import("../src/lib/quota-state.js");
    const { getProviders } = await import("../src/providers/registry.js");
    __resetQuotaStateForTests();

    const cursor = getProviders().find((provider) => provider.id === "cursor");
    if (!cursor) throw new Error("Missing production cursor provider");
    expect(cursor.cachePolicy).toEqual({ kind: "uncached" });
    vi.spyOn(cursor, "fetch")
      .mockResolvedValueOnce({
        attempted: true,
        entries: [
          {
            accounting: {
              resultType: "quota",
              acquisitionMethod: "remote_api",
              ownership: "maintained",
              authority: "provider_reported",
            },
            name: "Runtime A",
            percentRemaining: 80,
          },
        ],
        errors: [],
      })
      .mockResolvedValueOnce({
        attempted: true,
        entries: [
          {
            accounting: {
              resultType: "quota",
              acquisitionMethod: "remote_api",
              ownership: "maintained",
              authority: "provider_reported",
            },
            name: "Runtime B",
            percentRemaining: 40,
          },
        ],
        errors: [],
      });
    const runtimeA = createTestContext();
    const runtimeB = createTestContext();

    await fetchQuotaProviderResult({ provider: cursor, ctx: runtimeA, ttlMs: 60_000 });
    await expect(
      readCachedProviderResult({ provider: cursor, ctx: runtimeB, ttlMs: 60_000 }),
    ).resolves.toEqual({ hit: false });
    await fetchQuotaProviderResult({ provider: cursor, ctx: runtimeB, ttlMs: 60_000 });

    const [exportA, exportB] = await Promise.all([
      buildQuotaExport({ providers: [cursor], ctx: runtimeA, ttlMs: 60_000, fromCache: true }),
      buildQuotaExport({ providers: [cursor], ctx: runtimeB, ttlMs: 60_000, fromCache: true }),
    ]);
    expect(exportA.providers.cursor).toMatchObject({
      status: "ok",
      entries: [{ name: "Runtime A", percentRemaining: 80 }],
    });
    expect(exportB.providers.cursor).toMatchObject({
      status: "ok",
      entries: [{ name: "Runtime B", percentRemaining: 40 }],
    });
  });
});
