/**
 * SEC-001 regression tests for `POST /api/analyze`.
 *
 * Two distinct failures are pinned here:
 *
 *  1. Resolution — a link inside the workspace that points outside it must be
 *     rejected. A lexical `path.relative` check cannot see this, because the
 *     requested string really is under the workspace root.
 *  2. Hand-off — the route validated a canonical path and then launched the
 *     worker with the RAW request string. `launchAnalysisWorker` uses that value
 *     as the walk root, the lock key and the job's `repoPath`, so a link swapped
 *     between check and launch redirected traversal out of the workspace
 *     (TOCTOU). The tripwire at the bottom fails if that regresses.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PathContainmentError } from '../../src/core/security/path-containment.js';
import { resolveAnalyzeRepoPath } from '../../src/server/api.js';

let workspace: string;
let outside: string;
let symlinksAvailable = false;

const linkTarget = (target: string, link: string) =>
  fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');

beforeAll(async () => {
  workspace = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-analyze-ws-'));
  outside = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-analyze-outside-'));
  await fs.mkdir(path.join(workspace, 'project', 'src'), { recursive: true });
  await fs.writeFile(path.join(workspace, 'project', 'src', 'app.ts'), 'export {};', 'utf-8');
  await fs.writeFile(path.join(outside, 'private.ts'), 'export const secret = 1;', 'utf-8');
  try {
    await linkTarget(outside, path.join(workspace, 'escape'));
    await linkTarget(path.join(workspace, 'escape'), path.join(workspace, 'nested-escape'));
    symlinksAvailable = true;
  } catch {
    symlinksAvailable = false;
  }
});

afterAll(async () => {
  await fs.rm(workspace, { recursive: true, force: true });
  await fs.rm(outside, { recursive: true, force: true });
});

describe('resolveAnalyzeRepoPath', () => {
  it('accepts the workspace root itself', async () => {
    await expect(resolveAnalyzeRepoPath(workspace, workspace)).resolves.toBe(
      await fs.realpath(workspace),
    );
  });

  it('accepts a directory inside the workspace and returns its canonical form', async () => {
    const project = path.join(workspace, 'project');
    await expect(resolveAnalyzeRepoPath(project, workspace)).resolves.toBe(
      await fs.realpath(project),
    );
  });

  it('rejects a link that points outside the workspace', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    await expect(
      resolveAnalyzeRepoPath(path.join(workspace, 'escape'), workspace),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects a nested link that resolves outside the workspace', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    await expect(
      resolveAnalyzeRepoPath(path.join(workspace, 'nested-escape'), workspace),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects ../ traversal', async () => {
    await expect(
      resolveAnalyzeRepoPath(path.join(workspace, '..', path.basename(outside)), workspace),
    ).rejects.toBeInstanceOf(PathContainmentError);
  });

  it('rejects an absolute path outside the workspace', async () => {
    await expect(resolveAnalyzeRepoPath(outside, workspace)).rejects.toBeInstanceOf(
      PathContainmentError,
    );
  });

  it('fails safely for a path that does not exist', async () => {
    await expect(
      resolveAnalyzeRepoPath(path.join(workspace, 'missing'), workspace),
    ).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('the canonical result stays inside even if the link is later swapped', async (ctx) => {
    if (!symlinksAvailable) return ctx.skip();
    const link = path.join(workspace, 'swap-me');
    const inner = path.join(workspace, 'project');
    await linkTarget(inner, link);

    const canonical = await resolveAnalyzeRepoPath(link, workspace);
    expect(canonical).toBe(await fs.realpath(inner));

    // TOCTOU: repoint the link at the outside directory after validation. The
    // canonical string handed to the worker still names the in-tree directory,
    // which is why the worker must receive it instead of the request string.
    await fs.rm(link);
    await linkTarget(outside, link);

    const realAfterSwap = await fs.realpath(canonical);
    expect(realAfterSwap).toBe(await fs.realpath(inner));
    expect(realAfterSwap.startsWith(await fs.realpath(workspace))).toBe(true);
  });
});

describe('analyze route hand-off (static tripwire)', () => {
  it('launches the worker with the canonical path, never the raw request string', async () => {
    const apiSource = await fs.readFile(
      fileURLToPath(new URL('../../src/server/api.ts', import.meta.url)),
      'utf-8',
    );

    expect(apiSource).toContain('let targetPath = analyzeRepoPath;');
    expect(apiSource).not.toContain('let targetPath = repoLocalPath;');
  });
});
