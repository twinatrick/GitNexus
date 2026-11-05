/**
 * SEC-004 regression tests: air-gap mode must never fall back to `npx`.
 *
 * The historic behaviour advertised `GITNEXUS_NO_UPDATE_NOTIFIER=1` as if it
 * disabled networking, while the generated MCP entry could still be
 * `npx -y gitnexus@<version> mcp`, which downloads from the npm registry on
 * first run. Air-gap mode turns that silent fallback into a hard error.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

// `which`/`where` always fails: no local gitnexus binary is installed in the
// test environment, which is exactly the condition air-gap mode must reject.
const execFileSyncMock = vi.fn((): string => {
  throw new Error('not found');
});

vi.mock('child_process', () => ({
  execFile: vi.fn((...args: any[]) => {
    const callback = args.at(-1);
    if (typeof callback === 'function') callback(null, '', '');
  }),
  execFileSync: execFileSyncMock,
}));

let tempHome: string;
let originalHome: string | undefined;
let originalUserProfile: string | undefined;
let originalAppData: string | undefined;
let originalExitCode: number | string | undefined;

const setup = async () => import('../../src/cli/setup.js');

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  originalAppData = process.env.APPDATA;
  originalExitCode = process.exitCode;
  tempHome = await fs.mkdtemp(path.join(os.tmpdir(), 'gn-airgap-'));
  process.env.HOME = tempHome;
  process.env.USERPROFILE = tempHome;
  process.env.APPDATA = tempHome;
  delete process.env.GITNEXUS_AIR_GAP;
  delete process.env.GITNEXUS_ALLOW_NPX_FALLBACK;
  process.exitCode = undefined;
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.GITNEXUS_AIR_GAP;
  delete process.env.GITNEXUS_ALLOW_NPX_FALLBACK;
  process.exitCode = originalExitCode;
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  if (originalAppData === undefined) delete process.env.APPDATA;
  else process.env.APPDATA = originalAppData;
  await fs.rm(tempHome, { recursive: true, force: true });
});

describe('setup --air-gap', () => {
  it('hard-fails instead of falling back to npx when no binary is installed', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode', airGap: true });

    expect(process.exitCode).toBe(1);
    const written = stderr.mock.calls.map((call) => String(call[0])).join('\n');
    expect(written).toMatch(/gitnexus binary not found/i);
    expect(written).toMatch(/offline|local installation/i);
    expect(written).not.toMatch(/npx\s+-y/i);
  });

  it('does not write an editor MCP entry that would invoke npx', async () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode', airGap: true });

    const configPath = path.join(tempHome, '.config', 'opencode', 'opencode.json');
    await expect(fs.access(configPath)).rejects.toThrow();

    const pluginPath = path.join(tempHome, '.config', 'opencode', 'plugins', 'gitnexus.js');
    await expect(fs.access(pluginPath)).rejects.toThrow();
  });

  it('honours the GITNEXUS_AIR_GAP environment variable', async () => {
    process.env.GITNEXUS_AIR_GAP = '1';
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode' });

    expect(process.exitCode).toBe(1);
    expect(stderr.mock.calls.map((call) => String(call[0])).join('\n')).toMatch(
      /binary not found/i,
    );
  });

  it('accepts GITNEXUS_AIR_GAP=true as well', async () => {
    process.env.GITNEXUS_AIR_GAP = 'true';
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode' });

    expect(process.exitCode).toBe(1);
  });

  it('refuses the npx fallback by default even outside air-gap mode', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode' });

    expect(process.exitCode).toBe(1);
    expect(stderr.mock.calls.map((call) => String(call[0])).join('\n')).toMatch(
      /GITNEXUS_ALLOW_NPX_FALLBACK/,
    );
  });

  it('only writes the npx entry when GITNEXUS_ALLOW_NPX_FALLBACK=1', async () => {
    process.env.GITNEXUS_ALLOW_NPX_FALLBACK = '1';
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await fs.mkdir(path.join(tempHome, '.config', 'opencode'), { recursive: true });
    const { setupCommand } = await setup();

    await setupCommand({ codingAgent: 'opencode' });

    expect(process.exitCode).toBeUndefined();
    expect(stderr).not.toHaveBeenCalled();

    // Locate whichever config file the platform-specific target wrote and
    // confirm it still describes the (normal-mode) npx fallback.
    const relativeFiles = await fs.readdir(tempHome, { recursive: true });
    const jsonFiles = relativeFiles
      .filter((file) => file.endsWith('.json'))
      .map((file) => path.join(tempHome, file));
    let entry: { command?: string | string[]; args?: string[] } | undefined;
    for (const file of jsonFiles) {
      const parsed = JSON.parse(await fs.readFile(file, 'utf-8'));
      const candidate = parsed?.mcpServers?.gitnexus ?? parsed?.mcp?.gitnexus;
      if (candidate) {
        entry = candidate;
        break;
      }
    }
    expect(entry).toBeDefined();
    // OpenCode stores the whole argv in `command`; Claude-style targets split it
    // into `command` + `args`, and win32 wraps it as `cmd /c npx ...`.
    const parts = Array.isArray(entry?.command)
      ? entry.command
      : [entry?.command, ...(entry?.args ?? [])];
    const commandLine = parts.join(' ');
    expect(commandLine).toMatch(/npx/i);
    expect(parts).toContain('-y');
  });
});
