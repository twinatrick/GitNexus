/**
 * SEC-006 regression tests: existing storage directories are re-validated,
 * not just newly created ones. `mkdir(..., { mode: 0o700 })` is a no-op on an
 * existing directory, so an older release could leave `.gitnexus` world- or
 * group-readable forever.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  PRIVATE_DIRECTORY_MODE,
  PRIVATE_FILE_MODE,
  ensurePrivateDirectory,
  ensurePrivateFile,
} from '../../src/storage/private-dirs.js';

let tmp: string;

beforeAll(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-private-dirs-'));
});

afterAll(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

const modeOf = async (target: string): Promise<number> =>
  (await fs.stat(target)).mode & 0o777;

describe('ensurePrivateDirectory', () => {
  it('creates nested directories', async () => {
    const target = path.join(tmp, 'a', 'b', 'c');
    await ensurePrivateDirectory(target);
    expect((await fs.stat(target)).isDirectory()).toBe(true);
  });

  it('creates new directories with 0700 on POSIX', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'fresh');
    await ensurePrivateDirectory(target);
    expect(await modeOf(target)).toBe(PRIVATE_DIRECTORY_MODE);
  });

  it('tightens an existing over-permissive directory on POSIX', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'legacy');
    await fs.mkdir(target, { recursive: true, mode: 0o755 });
    await fs.chmod(target, 0o755);
    expect(await modeOf(target)).toBe(0o755);

    await ensurePrivateDirectory(target);

    expect(await modeOf(target)).toBe(PRIVATE_DIRECTORY_MODE);
  });

  it('leaves an already-private directory untouched', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'already-private');
    await fs.mkdir(target, { recursive: true, mode: 0o700 });
    await ensurePrivateDirectory(target);
    expect(await modeOf(target)).toBe(PRIVATE_DIRECTORY_MODE);
  });

  it('does not chmod through a symlink', async (ctx) => {
    const target = path.join(tmp, 'symlink-escape');
    const outside = path.join(tmp, 'outside-target');
    await fs.mkdir(outside, { recursive: true });
    if (process.platform !== 'win32') await fs.chmod(outside, 0o755);
    try {
      await fs.symlink(outside, target, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      return ctx.skip();
    }
    // Must not throw, but must also not follow the link.
    await ensurePrivateDirectory(target);
    if (process.platform !== 'win32') {
      expect(await modeOf(outside)).toBe(0o755);
    }
  });

  it('rejects a non-directory target instead of silently succeeding', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'not-a-dir');
    await fs.writeFile(target, 'x');
    await expect(ensurePrivateDirectory(target)).rejects.toThrow(/EEXIST|ENOTDIR|exists/i);
  });
});

/**
 * SEC-006 (files): `registry.json` and `config.json` written by an older
 * release keep their umask-derived mode. The file-level half of the fix must
 * tighten them on the next write, and must not follow a link to do it.
 */
describe('ensurePrivateFile', () => {
  it('tightens an existing over-permissive file on POSIX', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'registry.json');
    await fs.writeFile(target, '{}');
    await fs.chmod(target, 0o644);
    expect(await modeOf(target)).toBe(0o644);

    await ensurePrivateFile(target);

    expect(await modeOf(target)).toBe(PRIVATE_FILE_MODE);
  });

  it('leaves an already-private file untouched', async (ctx) => {
    if (process.platform === 'win32') return ctx.skip();
    const target = path.join(tmp, 'config-private.json');
    await fs.writeFile(target, '{}', { mode: 0o600 });
    await fs.chmod(target, 0o600);
    await ensurePrivateFile(target);
    expect(await modeOf(target)).toBe(PRIVATE_FILE_MODE);
  });

  it('does not chmod through a symlink', async (ctx) => {
    const outside = path.join(tmp, 'outside-file.json');
    const target = path.join(tmp, 'registry-link.json');
    await fs.writeFile(outside, '{}');
    if (process.platform !== 'win32') await fs.chmod(outside, 0o644);
    try {
      await fs.symlink(outside, target, 'file');
    } catch {
      return ctx.skip();
    }

    await ensurePrivateFile(target);

    if (process.platform !== 'win32') {
      expect(await modeOf(outside)).toBe(0o644);
    }
  });

  it('is a no-op for a missing file', async () => {
    await expect(ensurePrivateFile(path.join(tmp, 'does-not-exist.json'))).resolves.toBeUndefined();
  });
});
