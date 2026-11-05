/**
 * Single source of truth for the sensitive-file policy.
 *
 * Every path that can surface repository bytes to a caller — the indexer, MCP
 * `read_file`, MCP `grep`, `GET /api/file`, `GET /api/grep` — must consult
 * this module. Keeping the rules here is what prevents the historic drift
 * where one reader honoured a denylist and another did not (SEC-002).
 *
 * The policy is deny-by-default and can only be relaxed with an explicit
 * opt-in (`GITNEXUS_ALLOW_SECRET_READS=1`). Helpers accept a path in either
 * absolute or repository-relative form and normalise Windows separators, so
 * callers never need to guess which shape they hold.
 */

export const SECRET_READS_ENV = 'GITNEXUS_ALLOW_SECRET_READS';

/** Explicit opt-in for reading credential material. Defaults to denied. */
export function secretReadsAllowed(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[SECRET_READS_ENV] === '1';
}

/**
 * Templates that document the shape of a secret file without containing one.
 * These stay readable/indexable even when secret reads are disabled.
 */
const ALLOWED_TEMPLATE_BASENAMES = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
  '.env.defaults',
  '.env.dist',
]);

/** Exact basenames that hold credentials or credential-shaped data. */
const SENSITIVE_BASENAMES = new Set([
  '.env',
  '.git-credentials',
  '.htpasswd',
  '.netrc',
  '.npmrc',
  '.pgpass',
  '.pypirc',
  'access_tokens.db',
  'accesstokens.json',
  'application_default_credentials.json',
  'auth.json',
  'credentials',
  'credentials.db',
  'credentials.json',
  'id_dsa',
  'id_ecdsa',
  'id_ecdsa_sk',
  'id_ed25519',
  'id_ed25519_sk',
  'id_rsa',
  'secrets.json',
  'secrets.toml',
  'secrets.yaml',
  'secrets.yml',
  'tokens.json',
]);

/** File extensions that always denote private key material or key stores. */
const SENSITIVE_EXTENSION = /\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$/iu;

/**
 * Directories whose entire contents are credential material. A single
 * segment match is enough — a repository has no legitimate reason to leak
 * anything below `.ssh/` or `.aws/`.
 */
const SENSITIVE_DIRECTORY_SEGMENTS = new Set([
  '.aws',
  '.azure',
  '.docker',
  '.gnupg',
  '.kube',
  '.npm',
  '.password-store',
  '.pki',
  '.ssh',
  '.vault',
]);

/** Specific credential files inside an otherwise ordinary config tree. */
const SENSITIVE_PATH_SUFFIXES = [
  '.git/config',
  '.git/credentials',
  '.config/gcloud',
  '.config/gh',
  '.config/hub',
  '.config/op',
  '.config/sops',
];

function normalizePathLike(value: string): string {
  return value.replace(/\\/gu, '/').replace(/\/+/gu, '/').toLowerCase();
}

/** True when a directory name or relative directory path is credential-only. */
export function isSensitiveDirectory(value: string): boolean {
  const normalized = normalizePathLike(value).replace(/^\.\//u, '').replace(/\/+$/u, '');
  if (!normalized) return false;
  const segments = normalized.split('/').filter(Boolean);
  for (let i = 0; i < segments.length; i++) {
    if (SENSITIVE_DIRECTORY_SEGMENTS.has(segments[i] as string)) return true;
    // `.config/gcloud`, `.config/gh`, … are sensitive at the pair level.
    const pair = segments.slice(i, i + 2).join('/');
    if (pair === '.config/gcloud' || pair === '.config/gh' || pair === '.config/hub') {
      return true;
    }
    if (pair === '.config/op' || pair === '.config/sops') return true;
  }
  return false;
}

/**
 * True when a path must be treated as credential material. Accepts absolute
 * or repository-relative paths, on either platform.
 */
export function isSensitiveFile(value: string): boolean {
  const normalized = normalizePathLike(value);
  if (!normalized) return false;

  const basename = normalized.slice(normalized.lastIndexOf('/') + 1);
  if (!basename) return false;

  if (ALLOWED_TEMPLATE_BASENAMES.has(basename)) return false;

  if (basename === '.env' || basename.startsWith('.env.')) return true;
  if (SENSITIVE_BASENAMES.has(basename)) return true;
  if (SENSITIVE_EXTENSION.test(basename)) return true;

  const trimmed = normalized.replace(/^\/+/u, '');
  for (const suffix of SENSITIVE_PATH_SUFFIXES) {
    if (trimmed === suffix || trimmed.endsWith(`/${suffix}`)) return true;
  }

  return isSensitiveDirectory(normalized);
}
