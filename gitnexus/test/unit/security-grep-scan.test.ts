/**
 * SEC-001 / SEC-002 regression tests for the filesystem grep scan.
 *
 * `GET /api/grep` and the MCP `grep` tool both go through `scanGrepFiles`.
 * The index can be stale (built before hardening) and may list symlinks or
 * credential files, so the scan re-validates every path it opens.
 */
import { afterEach, beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { scanGrepFiles } from '../../src/server/grep-scan.js';

let root: string;
let outside: string;
let symlinksAvailable = false;

const scan = (filePaths: string[], pattern = 'secret', limit = 50) =>
  scanGrepFiles({
    repoRoot: root,
    filePaths,
    pattern,
    flags: 'i',
    limit,
    // Generous deadline; these fixtures are tiny.
    deadlineMs: Date.now() + 10_000,
  });

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-grep-root-'));
  outside = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-grep-outside-'));

  await fs.mkdir(path.join(root, 'src'), { recursive: true });
  await fs.writeFile(path.join(root, 'src', 'app.ts'), 'const secret = "safe fixture";\n');
  await fs.writeFile(path.join(root, '.env'), 'API_SECRET=super-secret-value\n');
  await fs.writeFile(path.join(root, '.env.local'), 'LOCAL_SECRET=another-secret\n');
  await fs.writeFile(path.join(root, 'credentials.json'), '{"secret":"json-secret"}\n');
  await fs.writeFile(path.join(root, 'id_rsa'), '-----BEGIN SECRET KEY-----\n');
  await fs.writeFile(path.join(root, 'tls.pem'), 'secret pem material\n');
  await fs.mkdir(path.join(root, '.ssh'), { recursive: true });
  await fs.writeFile(path.join(root, '.ssh', 'config'), 'secret ssh config\n');
  await fs.writeFile(path.join(outside, 'private.ts'), 'secret outside workspace\n');

  try {
    await fs.symlink(path.join(outside, 'private.ts'), path.join(root, 'escape.ts'), 'file');
    await fs.symlink(outside, path.join(root, 'escape-dir'), 'dir');
    symlinksAvailable = true;
  } catch {
    symlinksAvailable = false;
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
  await fs.rm(outside, { recursive: true, force: true });
});

describe('scanGrepFiles — sensitive files', () => {
  it('still matches ordinary source files', async () => {
    const { results } = await scan(['src/app.ts']);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ filePath: 'src/app.ts', line: 1 });
  });

  it.each(['.env', '.env.local', 'credentials.json', 'id_rsa', 'tls.pem', '.ssh/config'])(
    'never returns matches from %s, even when the index lists it',
    async (filePath) => {
      const { results } = await scan([filePath]);
      expect(results).toEqual([]);
    },
  );

  it('filters sensitive entries out of a mixed path list', async () => {
    const { results } = await scan(['.env', 'src/app.ts', 'credentials.json']);
    expect(results.map((hit) => hit.filePath)).toEqual(['src/app.ts']);
  });

  it('honours the explicit GITNEXUS_ALLOW_SECRET_READS=1 opt-in', async () => {
    vi.stubEnv('GITNEXUS_ALLOW_SECRET_READS', '1');
    const { results } = await scan(['.env']);
    expect(results).toHaveLength(1);
    expect(results[0]?.text).toContain('API_SECRET');
  });
});

describe('scanGrepFiles — path containment', () => {
  it('rejects ../ traversal entries', async () => {
    const { results } = await scan(['../outside/private.ts']);
    expect(results).toEqual([]);
  });

  it('rejects an absolute path outside the repository root', async () => {
    const { results } = await scan([path.join(outside, 'private.ts')]);
    expect(results).toEqual([]);
  });

  it('rejects a symlinked file that escapes the repository root', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const { results } = await scan(['escape.ts']);
    expect(results).toEqual([]);
  });

  it('rejects a file reached through an escaping symlinked directory', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const { results } = await scan(['escape-dir/private.ts']);
    expect(results).toEqual([]);
  });

  it('returns no results when the repository root itself cannot be resolved', async () => {
    const { results } = await scanGrepFiles({
      repoRoot: path.join(root, 'missing-repo'),
      filePaths: ['src/app.ts'],
      pattern: 'secret',
      flags: 'i',
      limit: 10,
      deadlineMs: Date.now() + 5_000,
    });
    expect(results).toEqual([]);
  });
});
