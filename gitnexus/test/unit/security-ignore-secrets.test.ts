/**
 * SEC-002 regression tests: `.gitnexusignore` negation must not be able to
 * re-enable credential material.
 *
 * This was the historic bypass: the indexer honoured the hardcoded denylist,
 * but a user-controlled `!.env` line (or a nested `.gitignore` negation) could
 * put a secret back into the graph, where the MCP/HTTP readers could reach it.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createIgnoreFilter } from '../../src/config/ignore-service.js';
import { isSensitiveFile } from '../../src/core/security/sensitive-files.js';

const withRepo = async (
  ignoreFile: string,
  run: (ignored: (p: string) => boolean, childIgnored: (p: string) => boolean) => void,
) => {
  const repo = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-ignore-'));
  try {
    await fs.writeFile(path.join(repo, '.gitnexusignore'), ignoreFile, 'utf-8');
    const filter = await createIgnoreFilter(repo);
    // The filter normally receives a path-scurry Path; these helpers mimic the
    // only part it uses (`relative()`).
    const asPath = (p: string) => ({ relative: () => p }) as never;
    run(
      (p) => filter.ignored(asPath(p)),
      (p) => filter.childrenIgnored(asPath(p)),
    );
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
};

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('createIgnoreFilter — credential deny-by-default', () => {
  it('ignores secrets by default', async () => {
    await withRepo('', (ignored) => {
      expect(ignored('.env')).toBe(true);
      expect(ignored('credentials.json')).toBe(true);
      expect(ignored('id_rsa')).toBe(true);
      expect(ignored('certs/server.pem')).toBe(true);
    });
  });

  it('cannot be overridden by a .gitnexusignore negation', async () => {
    await withRepo('!.env\n!credentials.json\n!id_rsa\n', (ignored) => {
      expect(ignored('.env')).toBe(true);
      expect(ignored('credentials.json')).toBe(true);
      expect(ignored('id_rsa')).toBe(true);
    });
  });

  it('cannot be overridden for files inside credential directories', async () => {
    await withRepo('!.ssh/\n!.ssh/config\n', (ignored, childIgnored) => {
      expect(ignored('.ssh/config')).toBe(true);
      expect(childIgnored('.ssh')).toBe(true);
    });
  });

  it('still allows ordinary sources and never treats templates as secrets', async () => {
    await withRepo('', (ignored) => {
      // Template files stay out of the index through the pre-existing ignore
      // list; what matters here is that they are not classified as credential
      // material, so the sensitive-file guard does not apply to them.
      expect(isSensitiveFile('.env.example')).toBe(false);
      expect(isSensitiveFile('config/.env.sample')).toBe(false);
      expect(ignored('src/index.ts')).toBe(false);
      expect(ignored('README.md')).toBe(false);
    });
  });

  it('keeps user negations working for non-sensitive paths', async () => {
    await withRepo('!generated/\n', (ignored) => {
      expect(ignored('generated/output.ts')).toBe(false);
    });
  });

  it('only relaxes the policy with the explicit opt-in', async () => {
    vi.stubEnv('GITNEXUS_ALLOW_SECRET_READS', '1');
    await withRepo('!.env\n', (ignored) => {
      // The hardcoded default list still excludes .env, but the negation is
      // now permitted to win — matching the documented opt-in behaviour.
      expect(ignored('.env')).toBe(false);
    });
  });
});
