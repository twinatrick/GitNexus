/**
 * `gitnexus setup` is OpenCode-only in this hardened fork.
 *
 * The Claude Code / Codex / Cursor installers (and the hook adapters they
 * copied) were dropped so the fork ships a single editor surface and no
 * bundled script can invoke `npx`. These tests pin that policy: the default
 * selection is OpenCode, legacy editor ids are rejected, and the
 * `GITNEXUS_SETUP_ALL_EDITORS` escape hatch no longer grants them.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { packageVersion } from '../../src/core/package-version.js';

const PKG_VERSION = packageVersion();

/** Flatten the spied console.log calls into one searchable string. */
const logLines = () =>
  vi
    .mocked(console.log)
    .mock.calls.map((call) => call.join(' '))
    .join('\n');

const errLines = () =>
  vi
    .mocked(process.stderr.write)
    .mock.calls.map((call) => String(call[0]))
    .join('');

// `which`/`where gitnexus` always fails, so the generated MCP entry takes the
// npx fallback — which is opt-in only, so these tests enable it explicitly
// (the default refusal and air-gap refusal are covered in setup-airgap.test.ts).
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
let originalExitCode: number | string | undefined;

const opencodeConfigPath = () => path.join(tempHome, '.config', 'opencode', 'opencode.json');
const opencodePluginPath = () =>
  path.join(tempHome, '.config', 'opencode', 'plugins', 'gitnexus.js');

const importSetup = async () => import('../../src/cli/setup.js');

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  originalExitCode = process.exitCode;
  tempHome = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-setup-'));
  process.env.HOME = tempHome;
  process.env.USERPROFILE = tempHome;
  delete process.env.GITNEXUS_AIR_GAP;
  delete process.env.GITNEXUS_SETUP_ALL_EDITORS;
  process.env.GITNEXUS_ALLOW_NPX_FALLBACK = '1';
  process.exitCode = undefined;
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(async () => {
  process.exitCode = originalExitCode;
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  delete process.env.GITNEXUS_AIR_GAP;
  delete process.env.GITNEXUS_SETUP_ALL_EDITORS;
  delete process.env.GITNEXUS_ALLOW_NPX_FALLBACK;
  vi.restoreAllMocks();
  await fs.rm(tempHome, { recursive: true, force: true });
});

const withOpencodeInstalled = async () => {
  await fs.mkdir(path.join(tempHome, '.config', 'opencode'), { recursive: true });
};

const readConfig = async () => JSON.parse(await fs.readFile(opencodeConfigPath(), 'utf-8'));

describe('setup (OpenCode-only policy)', () => {
  it('configures OpenCode by default when its config dir exists', async () => {
    await withOpencodeInstalled();
    const { setupCommand } = await importSetup();

    await setupCommand();

    const config = await readConfig();
    expect(config.mcp.gitnexus).toBeDefined();
    expect(logLines()).toMatch(/OpenCode/);
    await expect(fs.stat(opencodePluginPath())).resolves.toBeTruthy();
  });

  it('writes the npx fallback entry when it is explicitly enabled', async () => {
    await withOpencodeInstalled();
    const { setupCommand } = await importSetup();

    await setupCommand();

    const entry = (await readConfig()).mcp.gitnexus;
    expect(entry.type).toBe('local');
    const commandLine = [entry.command, ...(entry.commandArgs ?? entry.args ?? [])].join(' ');
    expect(commandLine).toMatch(/npx/i);
    expect(commandLine).toContain('-y');
    expect(commandLine).toContain(`gitnexus@${PKG_VERSION}`);
    expect(commandLine).toContain('mcp');
  });

  it('does not touch legacy editor configs', async () => {
    await withOpencodeInstalled();
    const { setupCommand } = await importSetup();

    await setupCommand();

    for (const dir of ['.claude', '.codex', '.cursor', '.codebuddy', '.qoder', '.factory']) {
      await expect(fs.stat(path.join(tempHome, dir))).rejects.toThrow();
    }
  });

  it('reports a skip when OpenCode is not installed', async () => {
    const { setupCommand } = await importSetup();

    await setupCommand();

    expect(logLines()).toMatch(/OpenCode \(not installed\)/);
    await expect(fs.stat(opencodeConfigPath())).rejects.toThrow();
  });

  it('fails when an explicit OpenCode selection cannot be configured', async () => {
    const { setupCommand } = await importSetup();

    await setupCommand({ codingAgent: 'opencode' });

    expect(process.exitCode).toBe(1);
    expect(errLines()).toMatch(/None of the explicitly selected coding agents were configured/);
  });

  it('rejects legacy editor ids', async () => {
    await withOpencodeInstalled();
    const { setupCommand } = await importSetup();

    await setupCommand({ codingAgent: 'claude' });

    expect(process.exitCode).toBe(1);
    expect(errLines()).toMatch(/Unknown: claude/);
    expect(errLines()).toMatch(/Valid values: opencode/);
    await expect(fs.stat(path.join(tempHome, '.claude'))).rejects.toThrow();
  });

  it('rejects the legacy comma-separated multi-editor selection', async () => {
    await withOpencodeInstalled();
    const { setupCommand } = await importSetup();

    await setupCommand({ codingAgent: 'opencode,codex' });

    expect(process.exitCode).toBe(1);
    expect(errLines()).toMatch(/Unknown: codex/);
  });

  it('ignores GITNEXUS_SETUP_ALL_EDITORS and stays OpenCode-only', async () => {
    await withOpencodeInstalled();
    process.env.GITNEXUS_SETUP_ALL_EDITORS = '1';
    const { setupCommand } = await importSetup();

    await setupCommand();

    expect((await readConfig()).mcp.gitnexus).toBeDefined();
    await expect(fs.stat(path.join(tempHome, '.claude'))).rejects.toThrow();
    await expect(fs.stat(path.join(tempHome, '.codex'))).rejects.toThrow();
  });

  it('preserves unrelated keys when merging the existing config', async () => {
    await withOpencodeInstalled();
    await fs.writeFile(
      opencodeConfigPath(),
      JSON.stringify(
        { theme: 'dark', mcp: { other: { type: 'local', command: ['/bin/other'] } } },
        null,
        2,
      ),
      'utf-8',
    );
    const { setupCommand } = await importSetup();

    await setupCommand();

    const config = await readConfig();
    expect(config.theme).toBe('dark');
    expect(config.mcp.other).toEqual({ type: 'local', command: ['/bin/other'] });
    expect(config.mcp.gitnexus).toBeDefined();
  });
});
