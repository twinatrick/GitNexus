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
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

/** True on platforms where POSIX mode bits are meaningful. */
function supportsPosixModes(): boolean {
  return process.platform !== 'win32';
}

export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });

  // Windows uses ACLs; chmod only toggles the read-only bit and would not
  // provide the intended protection.
  if (!supportsPosixModes()) {
    await tightenWindowsAcl(directory, 'dir');
    return;
  }

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

/**
 * Windows half of SEC-006. `mkdir`/`chmod` cannot express "owner only" on
 * Windows, and an inherited ACL from a permissive parent (a repo checkout on
 * D:\ or a shared drive) is exactly the exposure SEC-006 describes. `icacls`
 * with `/inheritance:r` drops the inherited entries and re-grants full control
 * to the current user only.
 *
 * Deliberately narrow: only paths under the user profile are touched. A repo
 * the operator keeps on another volume may be owned by a different account or
 * governed by a corporate ACL we must not rewrite, so that case is left alone
 * rather than silently re-permissioned.
 */
async function tightenWindowsAcl(target: string, kind: 'dir' | 'file'): Promise<void> {
  if (process.platform !== 'win32') return;
  const profile = process.env.USERPROFILE;
  if (!profile) return;
  const relative = path.relative(profile, path.resolve(target));
  if (relative.startsWith('..') || path.isAbsolute(relative)) return;

  const account =
    process.env.USERDOMAIN && process.env.USERNAME
      ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
      : process.env.USERNAME;
  if (!account) return;

  const grant = kind === 'dir' ? `${account}:(OI)(CI)F` : `${account}:F`;
  try {
    await execFileAsync('icacls', [target, '/inheritance:r', '/grant:r', grant], {
      windowsHide: true,
      timeout: 10_000,
    });
  } catch {
    /* best-effort: an unsupported FS or restricted account must not fail the write */
  }
}

/**
 * Restrict an existing sensitive FILE to its owner (SEC-006).
 *
 * `fs.writeFile(..., { mode: 0o600 })` only applies at creation. `registry.json`
 * and `config.json` written by an older release keep whatever the umask gave
 * them, so a second local user can still read URLs, aliases and API keys out of
 * them. Same guards as `ensurePrivateDirectory`: never chmod through a symlink,
 * never touch a file the current user does not own.
 */
export async function ensurePrivateFile(filePath: string): Promise<void> {
  let stats: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    stats = await fs.lstat(filePath);
  } catch {
    return;
  }

  if (stats.isSymbolicLink() || !stats.isFile()) return;

  if (!supportsPosixModes()) {
    await tightenWindowsAcl(filePath, 'file');
    return;
  }

  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (uid !== undefined && stats.uid !== uid) return;

  if ((stats.mode & 0o077) !== 0) {
    try {
      await fs.chmod(filePath, PRIVATE_FILE_MODE);
    } catch {
      /* best-effort */
    }
  }
}
