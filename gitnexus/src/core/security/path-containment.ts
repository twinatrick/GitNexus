/**
 * Canonical path-containment helpers (SEC-001).
 *
 * `path.resolve` / `path.relative` are purely lexical: they happily accept a
 * symlink that points outside the allowed workspace. Every boundary check that
 * gates filesystem traversal must therefore compare *real* paths. These
 * helpers centralise that rule so the HTTP API, the MCP policy, and the
 * regression tests cannot drift apart.
 */
import fs from 'node:fs/promises';
import path from 'node:path';

export class PathContainmentError extends Error {
  readonly code = 'PATH_OUTSIDE_WORKSPACE';

  constructor(message = 'Path is outside the allowed workspace') {
    super(message);
    this.name = 'PathContainmentError';
  }
}

/** True when `target` is the root itself or lives below it (lexical). */
export function isLexicallyInside(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

/**
 * Resolve both sides and reject anything that escapes via `..` or a symlink.
 * Returns the canonical target so callers can operate on the path they
 * actually validated (shrinking the symlink-swap window).
 *
 * @throws PathContainmentError when the target resolves outside `root`
 * @throws NodeJS.ErrnoException (ENOENT) when either side cannot be resolved
 */
export async function resolveContainedPath(root: string, target: string): Promise<string> {
  const [realRoot, realTarget] = await Promise.all([
    fs.realpath(path.resolve(root)),
    fs.realpath(path.resolve(target)),
  ]);

  if (!isLexicallyInside(realRoot, realTarget)) {
    throw new PathContainmentError();
  }

  return realTarget;
}
