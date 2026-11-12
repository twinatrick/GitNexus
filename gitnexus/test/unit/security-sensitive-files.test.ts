/**
 * SEC-002 regression tests for the shared sensitive-file policy.
 *
 * The policy is the single source of truth consumed by the indexer, the MCP
 * file/grep tools, and the HTTP file/grep routes. These tests pin the exact
 * deny/allow boundary so a future edit cannot silently weaken one surface.
 */
import { describe, expect, it } from 'vitest';
import {
  SECRET_READS_ENV,
  isSensitiveDirectory,
  isSensitiveFile,
  secretReadsAllowed,
} from '../../src/core/security/sensitive-files.js';

describe('secretReadsAllowed', () => {
  it('denies secret reads by default', () => {
    expect(secretReadsAllowed({})).toBe(false);
  });

  it('only accepts the explicit "1" opt-in', () => {
    expect(secretReadsAllowed({ [SECRET_READS_ENV]: '1' })).toBe(true);
    expect(secretReadsAllowed({ [SECRET_READS_ENV]: 'true' })).toBe(false);
    expect(secretReadsAllowed({ [SECRET_READS_ENV]: '0' })).toBe(false);
    expect(secretReadsAllowed({ [SECRET_READS_ENV]: '' })).toBe(false);
  });
});

describe('isSensitiveFile', () => {
  it.each([
    '.env',
    '.env.local',
    '.env.production',
    'config/.env.staging',
    'credentials.json',
    'secrets.json',
    'secrets.yaml',
    'tokens.json',
    'auth.json',
    'id_rsa',
    'id_ed25519',
    '.npmrc',
    '.netrc',
    '.git-credentials',
    'certs/server.pem',
    'certs/server.key',
    'certs/bundle.p12',
    'certs/bundle.pfx',
    'store.jks',
    'store.keystore',
    'vault.kdbx',
  ])('blocks %s', (filePath) => {
    expect(isSensitiveFile(filePath)).toBe(true);
  });

  it.each([
    'src/index.ts',
    'README.md',
    'docs/credentials.md',
    'src/secret-manager.ts',
    'environment.ts',
    '.env.example',
    '.env.sample',
    '.env.template',
    '.env.dist',
    'config/.env.defaults',
  ])('allows %s', (filePath) => {
    expect(isSensitiveFile(filePath)).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isSensitiveFile('CONFIG/CREDENTIALS.JSON')).toBe(true);
    expect(isSensitiveFile('Certs/Server.PEM')).toBe(true);
  });

  it('normalises Windows separators', () => {
    expect(isSensitiveFile('config\\credentials.json')).toBe(true);
    expect(isSensitiveFile('C:\\repo\\.env.local')).toBe(true);
  });

  it('blocks files inside credential directories even when named like a template', () => {
    expect(isSensitiveFile('.ssh/config')).toBe(true);
    expect(isSensitiveFile('home/.aws/credentials')).toBe(true);
    expect(isSensitiveFile('.config/gcloud/application_default_credentials.json')).toBe(true);
    expect(isSensitiveFile('.gnupg/private-keys-v1.d/key.key')).toBe(true);
    expect(isSensitiveFile('.ssh/.env.example')).toBe(true);
    expect(isSensitiveFile('.aws/.env.sample')).toBe(true);
    expect(isSensitiveFile('.env.example')).toBe(false);
    expect(isSensitiveFile('config/.env.example')).toBe(false);
  });

  it('blocks the repository credential store', () => {
    expect(isSensitiveFile('.git/config')).toBe(true);
    expect(isSensitiveFile('.git/credentials')).toBe(true);
  });
});

describe('isSensitiveDirectory', () => {
  it.each(['.ssh', '.aws', '.gnupg', '.kube', 'nested/.config/gh', '.config/sops'])(
    'marks %s as credential-only',
    (dir) => {
      expect(isSensitiveDirectory(dir)).toBe(true);
    },
  );

  it.each(['src', 'docs', '.config', '.github', 'credentials-helpers'])(
    'leaves %s traversable',
    (dir) => {
      expect(isSensitiveDirectory(dir)).toBe(false);
    },
  );
});
