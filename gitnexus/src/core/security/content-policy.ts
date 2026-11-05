/**
 * Content-serving policy (SEC-002, read side).
 *
 * `sensitive-files.ts` answers "may this PATH be read". Every surface that
 * returns repository bytes must ask it — including surfaces that never open a
 * file: the graph endpoints and the MCP `query` / `context` tools serve the
 * `content` column the indexer persisted earlier. Exclusion at index time is
 * not enough, for two reasons:
 *
 *  - indexes built by an older release still contain the rows, and
 *  - an index built with GITNEXUS_ALLOW_SECRET_READS=1 contains them too, even
 *    though the operator may have dropped the opt-in since.
 *
 * A path-based check at read time is therefore the only control that covers
 * pre-existing indexes without forcing a rebuild. This module is the single
 * implementation so the HTTP graph, MCP `query`, and MCP `context` cannot
 * drift apart the way the file readers did before SEC-002.
 */
import { isSensitiveFile, secretReadsAllowed } from './sensitive-files.js';

/**
 * Bumped whenever the set of paths excluded at index time changes. Stamped
 * into index metadata so a reader can tell a current index from one that
 * predates the policy; a stale stamp is reported (never silently trusted).
 */
export const SECURITY_CONTENT_POLICY_VERSION = 1;

/**
 * True when `content` for `filePath` may be returned to a caller.
 *
 * Absent paths are allowed: the graph has node kinds that carry content
 * without a file (or carry no content at all), and refusing those would break
 * unrelated labels without protecting anything.
 */
export function contentAllowedForPath(
  filePath: string | null | undefined,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (!filePath) return true;
  if (!isSensitiveFile(filePath)) return true;
  return secretReadsAllowed(env);
}

/**
 * Metadata-side half of the policy. `undefined` means the index predates the
 * stamp; anything below the current version was written under an older
 * exclusion list. Absence is NOT treated as "current" — the same direction
 * `contentRetentionSchemaVersion` already takes.
 */
export function needsContentPolicyReindex(meta: {
  securityPolicyVersion?: number;
} | null | undefined): boolean {
  return (meta?.securityPolicyVersion ?? 0) < SECURITY_CONTENT_POLICY_VERSION;
}

/** Human-readable warning shared by the surfaces that report suppressions. */
export function suppressedContentWarning(suppressed: number, reindexRequired: boolean): string {
  const base =
    `Withheld source content for ${suppressed} sensitive file${suppressed === 1 ? '' : 's'} ` +
    '(.env, credentials, keys, …) by security policy. ' +
    'Set GITNEXUS_ALLOW_SECRET_READS=1 to opt in.';
  return reindexRequired
    ? `${base} This index predates the current content policy; re-run \`gitnexus analyze\` to drop sensitive rows from it.`
    : base;
}
