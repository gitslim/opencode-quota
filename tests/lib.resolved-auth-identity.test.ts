import { chmod, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TEST_RUNTIME_ROOT = "/tmp/opencode-quota-resolved-auth-identity-tests";
const TEST_SYMLINK_TARGET = `${TEST_RUNTIME_ROOT}-symlink-target`;

vi.mock("../src/lib/opencode-runtime-paths.js", () => ({
  getOpencodeRuntimeDirs: () => ({
    dataDir: `${TEST_RUNTIME_ROOT}/data`,
    configDir: `${TEST_RUNTIME_ROOT}/config`,
    cacheDir: `${TEST_RUNTIME_ROOT}/cache`,
    stateDir: `${TEST_RUNTIME_ROOT}/state`,
  }),
}));

describe("resolved-auth identity", () => {
  beforeEach(async () => {
    vi.resetModules();
    await Promise.all([
      rm(TEST_RUNTIME_ROOT, { recursive: true, force: true }),
      rm(TEST_SYMLINK_TARGET, { recursive: true, force: true }),
    ]);
  });

  afterEach(async () => {
    vi.resetModules();
    await Promise.all([
      rm(TEST_RUNTIME_ROOT, { recursive: true, force: true }),
      rm(TEST_SYMLINK_TARGET, { recursive: true, force: true }),
    ]);
  });

  it("derives stable provider-scoped opaque identities without exposing principal material", async () => {
    const identity = await import("../src/lib/resolved-auth-identity.js");
    const first = await identity.deriveResolvedAuthIdentity({
      providerId: "zai",
      principal: { kind: "credential", value: "account-one-secret" },
    });
    const repeat = await identity.deriveResolvedAuthIdentity({
      providerId: "zai",
      principal: { kind: "credential", value: "account-one-secret" },
    });
    const changedAccount = await identity.deriveResolvedAuthIdentity({
      providerId: "zai",
      principal: { kind: "credential", value: "account-two-secret" },
    });
    const changedProvider = await identity.deriveResolvedAuthIdentity({
      providerId: "zhipu",
      principal: { kind: "credential", value: "account-one-secret" },
    });

    expect(identity.isResolvedAuthIdentity(first)).toBe(true);
    expect(first).toBe(repeat);
    expect(changedAccount).not.toBe(first);
    expect(changedProvider).not.toBe(first);
    expect(first).not.toContain("account-one-secret");
  });

  it("composes multi-account identities in deterministic order", async () => {
    const identity = await import("../src/lib/resolved-auth-identity.js");
    const first = await identity.deriveResolvedAuthIdentity({
      providerId: "google-agy",
      principal: { kind: "stable-id", value: "project-a\0one@example.com" },
    });
    const second = await identity.deriveResolvedAuthIdentity({
      providerId: "google-agy",
      principal: { kind: "stable-id", value: "project-b\0two@example.com" },
    });
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    if (!first || !second) throw new Error("Expected durable test identities");

    const ordered = await identity.composeResolvedAuthIdentities({
      providerId: "google-agy",
      identities: [first, second],
    });
    const repeat = await identity.composeResolvedAuthIdentities({
      providerId: "google-agy",
      identities: [first, second],
    });
    const reversed = await identity.composeResolvedAuthIdentities({
      providerId: "google-agy",
      identities: [second, first],
    });

    expect(ordered).toBe(repeat);
    expect(reversed).not.toBe(ordered);
    expect(JSON.stringify({ ordered })).not.toContain("one@example.com");
    expect(JSON.stringify({ ordered })).not.toContain("project-a");
  });

  it("creates one private durable key during concurrent first use", async () => {
    const identity = await import("../src/lib/resolved-auth-identity.js");
    const values = await Promise.all(
      Array.from({ length: 12 }, () =>
        identity.deriveResolvedAuthIdentity({
          providerId: "synthetic",
          principal: { kind: "credential", value: "shared-secret" },
        }),
      ),
    );

    expect(new Set(values).size).toBe(1);
    const keyPath = identity.getResolvedAuthIdentityKeyPath();
    const raw = await readFile(keyPath, "utf8");
    expect(raw).toMatch(/^v1:[A-Za-z0-9_-]{43}\n$/u);
    expect(raw).not.toContain("shared-secret");
    if (process.platform !== "win32") {
      expect((await stat(dirname(keyPath))).mode & 0o777).toBe(0o700);
      expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
    }
  });

  it("converges isolated module instances through exclusive key creation", async () => {
    const firstModule = await import("../src/lib/resolved-auth-identity.js");
    vi.resetModules();
    const secondModule = await import("../src/lib/resolved-auth-identity.js");

    const [first, second] = await Promise.all([
      firstModule.deriveResolvedAuthIdentity({
        providerId: "zai",
        principal: { kind: "credential", value: "shared-process-secret" },
      }),
      secondModule.deriveResolvedAuthIdentity({
        providerId: "zai",
        principal: { kind: "credential", value: "shared-process-secret" },
      }),
    ]);

    expect(first).not.toBeNull();
    expect(second).toBe(first);
    expect(await readFile(firstModule.getResolvedAuthIdentityKeyPath(), "utf8")).toMatch(
      /^v1:[A-Za-z0-9_-]{43}\n$/u,
    );
  });

  it("refuses a symlinked key directory instead of redirecting key creation", async () => {
    const identity = await import("../src/lib/resolved-auth-identity.js");
    const keyPath = identity.getResolvedAuthIdentityKeyPath();
    await mkdir(dirname(dirname(keyPath)), { recursive: true });
    await mkdir(TEST_SYMLINK_TARGET, { recursive: true });
    await symlink(TEST_SYMLINK_TARGET, dirname(keyPath), "dir");

    const resolved = await identity.deriveResolvedAuthIdentity({
      providerId: "zai",
      principal: { kind: "credential", value: "must-not-leave-the-state-root" },
    });

    expect(resolved).toBeNull();
    await expect(
      readFile(`${TEST_SYMLINK_TARGET}/resolved-auth-key-v1`, "utf8"),
    ).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("tightens an existing key file and refuses malformed key material", async () => {
    const identity = await import("../src/lib/resolved-auth-identity.js");
    const keyPath = identity.getResolvedAuthIdentityKeyPath();
    await mkdir(dirname(keyPath), { recursive: true });
    await writeFile(keyPath, "not-a-valid-key\n", { mode: 0o666 });
    if (process.platform !== "win32") await chmod(keyPath, 0o666);

    const resolved = await identity.deriveResolvedAuthIdentity({
      providerId: "zai",
      principal: { kind: "credential", value: "must-not-be-hashed-with-fallback" },
    });

    expect(resolved).toBeNull();
    expect(await readFile(keyPath, "utf8")).toBe("not-a-valid-key\n");
    if (process.platform !== "win32") {
      expect((await stat(keyPath)).mode & 0o777).toBe(0o600);
    }
  });
});
