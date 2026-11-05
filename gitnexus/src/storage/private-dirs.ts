/**
 * Private-directory enforcement (SEC-006).
 *
 * `fs.mkdir(dir, { mode: 0o700 })` only applies the mode when the directory is
 * created. A `.gitnexus` directory left behind by an older release keeps its
 * original (often 0755) mode forever, so every local user can read the index,
 * registry, and config. This helper re-validates existing directories and
 * tightens them to 0700 — without following symlinks and without touching
 * directories the current user does not own.
 */
import fs from 'node:fs/promises';

export const PRIVATE_DIRECTORY_MODE = 0o700;

/** True on platforms where POSIX mode bits are meaningful. */
function supportsPosixModes(): boolean {
  return process.platform !== 'win32';
}

export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });

  // Windows uses ACLs; chmod only toggles the read-only bit and would not
  // provide the intended protection.
  if (!supportsPosixModes()) return;

  let stats: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    stats = await fs.lstat(directory);
  } catch {
    return;
  }

  // Never chmod through a symlink: the link target may be outside our tree.
  if (stats.isSymbolicLink() || !stats.isDirectory()) return;

  // Only manage directories owned by the current user.
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (uid !== undefined && stats.uid !== uid) return;

  if ((stats.mode & 0o077) !== 0) {
    try {
      await fs.chmod(directory, PRIVATE_DIRECTORY_MODE);
    } catch {
      /* best-effort: reading an over-permissive dir is still possible */
    }
  }
}
