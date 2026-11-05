/**
 * SEC-002 (read side) regression tests.
 *
 * The index-time exclusion list was already applied to the walker, but the
 * surfaces that serve the persisted `content` column — `/api/graph`,
 * `streamGraphNdjson`, MCP `query` and MCP `context` — never consulted it. An
 * index built before the exclusion list existed (or built with
 * `GITNEXUS_ALLOW_SECRET_READS=1` and later withdrawn) still held `.env` rows
 * and served them verbatim.
 *
 * The previous behaviour these tests pin against: `includeContent: true`
 * returned the file body regardless of `filePath`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  SECURITY_CONTENT_POLICY_VERSION,
  contentAllowedForPath,
  needsContentPolicyReindex,
  suppressedContentWarning,
} from '../../src/core/security/content-policy.js';
import { mapGraphNodeRow } from '../../src/server/api.js';

describe('contentAllowedForPath', () => {
  it('allows ordinary source files', () => {
    expect(contentAllowedForPath('src/app.ts')).toBe(true);
    expect(contentAllowedForPath('docs/readme.md')).toBe(true);
  });

  it('allows nodes that carry no file path', () => {
    expect(contentAllowedForPath(undefined)).toBe(true);
    expect(contentAllowedForPath(null)).toBe(true);
    expect(contentAllowedForPath('')).toBe(true);
  });

  it('denies secret files by default', () => {
    for (const file of [
      '.env',
      '.env.production',
      'config/credentials.json',
      'secrets.json',
      'id_rsa',
      'certs/server.pem',
      'certs/server.key',
      'bundle.p12',
      '.ssh/config',
    ]) {
      expect(contentAllowedForPath(file), file).toBe(false);
    }
  });

  it('is case- and separator-insensitive', () => {
    expect(contentAllowedForPath('.ENV')).toBe(false);
    expect(contentAllowedForPath('config\\.env')).toBe(false);
    expect(contentAllowedForPath('config\\credentials.JSON')).toBe(false);
  });

  it('still allows non-secret templates', () => {
    expect(contentAllowedForPath('.env.example')).toBe(true);
    expect(contentAllowedForPath('.env.sample')).toBe(true);
  });

  it('honours the explicit GITNEXUS_ALLOW_SECRET_READS opt-in only', () => {
    expect(contentAllowedForPath('.env', {})).toBe(false);
    expect(contentAllowedForPath('.env', { GITNEXUS_ALLOW_SECRET_READS: '0' })).toBe(false);
    expect(contentAllowedForPath('.env', { GITNEXUS_ALLOW_SECRET_READS: 'true' })).toBe(false);
    expect(contentAllowedForPath('.env', { GITNEXUS_ALLOW_SECRET_READS: '1' })).toBe(true);
  });
});

describe('needsContentPolicyReindex', () => {
  it('treats a missing stamp as stale, not current', () => {
    expect(needsContentPolicyReindex(undefined)).toBe(true);
    expect(needsContentPolicyReindex(null)).toBe(true);
    expect(needsContentPolicyReindex({})).toBe(true);
  });

  it('accepts an index stamped with the current version', () => {
    expect(needsContentPolicyReindex({ securityPolicyVersion: SECURITY_CONTENT_POLICY_VERSION })).toBe(
      false,
    );
  });

  it('rejects an older stamp', () => {
    expect(needsContentPolicyReindex({ securityPolicyVersion: 0 })).toBe(true);
  });
});

describe('suppressedContentWarning', () => {
  it('names the withheld count and the opt-in', () => {
    const warning = suppressedContentWarning(3, false);
    expect(warning).toContain('3');
    expect(warning).toContain('GITNEXUS_ALLOW_SECRET_READS=1');
    expect(warning).not.toMatch(/re-run/);
  });

  it('adds the reindex hint only for stale indexes', () => {
    expect(suppressedContentWarning(1, true)).toMatch(/re-run `gitnexus analyze`/);
    expect(suppressedContentWarning(1, false)).not.toMatch(/re-run/);
  });
});

describe('graph node mapping withholds sensitive content (SEC-002)', () => {
  it('drops content for a secret file even when includeContent is true', () => {
    const node = mapGraphNodeRow('File', { id: 'f1', filePath: '.env', content: 'AWS_KEY=x' }, true);
    expect(node.properties.content).toBeUndefined();
  });

  it('keeps content for an ordinary file', () => {
    const node = mapGraphNodeRow(
      'File',
      { id: 'f2', filePath: 'src/app.ts', content: 'export {};' },
      true,
    );
    expect(node.properties.content).toBe('export {};');
  });

  it('does not leak content when includeContent is false', () => {
    const node = mapGraphNodeRow(
      'File',
      { id: 'f3', filePath: 'src/app.ts', content: 'export {};' },
      false,
    );
    expect(node.properties.content).toBeUndefined();
  });
});

/**
 * The indexer stamps `securityPolicyVersion` so a reader can tell a current
 * index from one that predates the exclusion list. Without that stamp the
 * warning above has no reindex hint and the staleness is invisible.
 */
describe('index metadata stamp', () => {
  let tmpRoot: string;

  beforeAll(async () => {
    tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-content-policy-'));
  });

  afterAll(async () => {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  });

  it('treats a legacy meta.json as requiring reindex', async () => {
    const metaDir = path.join(tmpRoot, '.gitnexus');
    await fs.mkdir(metaDir, { recursive: true });
    const metaPath = path.join(metaDir, 'meta.json');
    await fs.writeFile(
      metaPath,
      JSON.stringify({ repoPath: tmpRoot, storagePath: metaDir }, null, 2),
      'utf-8',
    );

    const meta = JSON.parse(await fs.readFile(metaPath, 'utf-8'));
    expect(needsContentPolicyReindex(meta)).toBe(true);
  });
});
