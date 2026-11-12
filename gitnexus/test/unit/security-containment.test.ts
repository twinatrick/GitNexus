/**
 * SEC-001 regression tests: canonical (realpath) containment for local
 * analyze paths.
 *
 * `path.resolve`/`path.relative` alone cannot see symlinks, so a repository
 * containing `external -> /some/other/project` would let `POST /api/analyze`
 * index a directory outside the workspace. These tests pin the realpath
 * behaviour and the "return the canonical path" contract that closes the
 * check/use race.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  PathContainmentError,
  isLexicallyInside,
  resolveContainedPath,
} from '../../src/core/security/path-containment.js';
import { resolveAnalyzeRepoPath } from '../../src/server/api.js';

let root: string;
let outside: string;
let symlinksAvailable = false;

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-containment-root-'));
  outside = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-containment-outside-'));

  await fs.mkdir(path.join(root, 'project', 'src'), { recursive: true });
  await fs.writeFile(path.join(root, 'project', 'index.ts'), 'export {};\n', 'utf-8');
  await fs.writeFile(path.join(outside, 'private.ts'), '// private\n', 'utf-8');

  try {
    await fs.symlink(outside, path.join(root, 'project', 'external'), 'dir');
    await fs.symlink(
      path.join(outside, 'private.ts'),
      path.join(root, 'project', 'external-file.ts'),
      'file',
    );
    await fs.symlink(path.join(root, 'project', 'src'), path.join(root, 'project', 'alias'), 'dir');
    symlinksAvailable = true;
  } catch {
    symlinksAvailable = false;
  }
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
  await fs.rm(outside, { recursive: true, force: true });
});

describe('isLexicallyInside', () => {
  it('accepts the root itself and descendants', () => {
    expect(isLexicallyInside('/workspace', '/workspace')).toBe(true);
    expect(isLexicallyInside('/workspace', '/workspace/project-a')).toBe(true);
  });

  it('rejects siblings, prefixes, and parent traversal', () => {
    expect(isLexicallyInside('/workspace', '/workspace-evil/x')).toBe(false);
    expect(isLexicallyInside('/workspace', '/workspace/../etc')).toBe(false);
    expect(isLexicallyInside('/workspace', '/etc/passwd')).toBe(false);
  });
});

describe('resolveContainedPath', () => {
  it('accepts the workspace root and a normal subdirectory', async () => {
    await expect(resolveContainedPath(root, root)).resolves.toBe(await fs.realpath(root));
    const project = path.join(root, 'project');
    await expect(resolveContainedPath(root, project)).resolves.toBe(await fs.realpath(project));
  });

  it('rejects ../ traversal', async () => {
    await expect(resolveContainedPath(root, path.join(root, '..'))).rejects.toBeInstanceOf(
      PathContainmentError,
    );
  });

  it('rejects an absolute path outside the workspace', async () => {
    await expect(resolveContainedPath(root, outside)).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects a symlink that points outside the workspace', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    await expect(
      resolveContainedPath(root, path.join(root, 'project', 'external')),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects a file reached through an escaping symlinked directory', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    await expect(
      resolveContainedPath(root, path.join(root, 'project', 'external', 'private.ts')),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects a nested symlink chain that ends outside the workspace', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const link = path.join(root, 'project', 'chain');
    await fs.symlink(path.join(root, 'project', 'external'), link, 'dir');
    try {
      await expect(
        resolveContainedPath(root, path.join(link, 'private.ts')),
      ).rejects.toBeInstanceOf(PathContainmentError);
    } finally {
      await fs.rm(link, { force: true });
    }
  });

  it('accepts an in-workspace symlink and returns its real target', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const resolved = await resolveContainedPath(root, path.join(root, 'project', 'alias'));
    expect(resolved).toBe(await fs.realpath(path.join(root, 'project', 'src')));
  });

  it('fails with ENOENT for a missing path instead of throwing an unhandled error', async () => {
    await expect(
      resolveContainedPath(root, path.join(root, 'does-not-exist')),
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('resolveAnalyzeRepoPath (POST /api/analyze boundary)', () => {
  it('returns the canonical path for a valid repository', async () => {
    const project = path.join(root, 'project');
    await expect(resolveAnalyzeRepoPath(project, root)).resolves.toBe(await fs.realpath(project));
  });

  it('rejects a symlinked repository outside the workspace', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    await expect(
      resolveAnalyzeRepoPath(path.join(root, 'project', 'external'), root),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('snapshots the canonical target so a later symlink swap cannot retarget it', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const original = await resolveAnalyzeRepoPath(path.join(root, 'project', 'alias'), root);
    // Simulate a racing attacker retargeting the symlink after the check.
    const alias = path.join(root, 'project', 'alias');
    await fs.rm(alias, { force: true });
    await fs.symlink(outside, alias, 'dir');
    try {
      // The value handed to the job still names the original in-workspace dir.
      expect(original).toBe(await fs.realpath(path.join(root, 'project', 'src')));
      expect(original).not.toBe(await fs.realpath(outside));
    } finally {
      await fs.rm(alias, { force: true });
      await fs.symlink(path.join(root, 'project', 'src'), alias, 'dir');
    }
  });
});

describe.runIf(process.platform === 'win32')('Windows junctions', () => {
  it('rejects a junction that points outside the workspace', async (ctx) => {
    const junction = path.join(root, 'project', 'junction-out');
    try {
      await fs.symlink(outside, junction, 'junction');
    } catch {
      return ctx.skip();
    }
    try {
      await expect(resolveContainedPath(root, junction)).rejects.toBeInstanceOf(
        PathContainmentError,
      );
    } finally {
      await fs.rm(junction, { recursive: true, force: true });
    }
  });
});
