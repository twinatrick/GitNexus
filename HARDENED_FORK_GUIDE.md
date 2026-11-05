# GitNexus (Hardened OpenCode Security Fork)

This fork of `abhigyanpatwari/GitNexus` (`v1.6.12`) implements the security and OpenCode compatibility hardening documented in `ADR-0001`, `ADR-0002`, and `ADR-0003`:

1. **Zero Install/Runtime Telemetry & Egress**:
   - Removed `@scarf/scarf` from `gitnexus/package.json`.
   - Disabled implicit background `registry.npmjs.org` update checks in CLI and `serve` modes unless `GITNEXUS_ENABLE_UPDATE_CHECK=1` is explicitly set.
2. **Secure-by-Default MCP Policy (`ADR-0002`)**:
   - `GITNEXUS_MCP_READ_ONLY` defaults to `true` (disables raw `cypher`, `refresh_index`, `group_*`, and forces `rename` to preview-only `dry_run: true`). Set `GITNEXUS_MCP_READ_ONLY=0` only when write tools are intentionally required.
   - `createMcpRepositoryPolicy` automatically scopes accessible repositories to the active workspace (`process.cwd()`) rather than exposing all historic repositories in `~/.gitnexus/registry.json`.
3. **Out-of-Tree Symlink Containment & Sensitive Secret File Denylist**:
   - `filesystem-walker.ts` resolves `fs.realpath` for every candidate file and rejects any symlink escaping `repoPath`.
   - `filesystem-walker.ts`, MCP `read_file`, and HTTP `/api/file` block reading or indexing sensitive secret/credential files (`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `.npmrc`, `.netrc`, `.git/config`, `.git/credentials`) unless `GITNEXUS_ALLOW_SECRET_READS=1`.
4. **Local HTTP API (`gitnexus serve`) Hardening (`ADR-0003`)**:
   - Removed `Access-Control-Allow-Private-Network: true` and stripped RFC 1918 LAN / `vercel.app` CORS origins. Only strict loopback origins (`localhost` / `127.0.0.1`) are allowed.
   - Enforced `requireTrustedOrigin` and read-only policy on `POST /api/query`, and restricted `POST /api/analyze` to workspace directories (with remote URL cloning disabled unless `GITNEXUS_ALLOW_REMOTE_CLONE=1`).
5. **OpenCode-Only Setup & 0o700 Storage Permissions**:
   - `gitnexus setup` configures OpenCode only (`~/.config/opencode/`). The legacy editor ids (`claude`, `codex`, `cursor`, `codebuddy`, `qoder`, `droid`, `antigravity`) are rejected with `Unknown: <id>. Valid values: opencode.` — the fork no longer ships their hook adapters, so registering one would leave the editor pointing at a hook that cannot run. The former `GITNEXUS_SETUP_ALL_EDITORS` escape hatch is removed.
   - Index and registry directories (`.gitnexus`, `~/.gitnexus`) are created with `mode: 0o700` (owner-only).
6. **Untrusted Repository Metadata Boundary**:
   - Wrapped `augment` and MCP `getNextStepHint` outputs in `<untrusted_repo_metadata>` tags after neutralizing XML/control characters and fake `[GitNexus]` prefixes.
7. **PR #1 Security Remediation (`SEC-001` ~ `SEC-006`)**:
   - **Shared secret policy (`SEC-002`)**: `gitnexus/src/core/security/sensitive-files.ts` owns `isSensitiveFile()`, `isSensitiveDirectory()` and `secretReadsAllowed()`. The HTTP `/api/file` route, the HTTP and MCP `grep` paths, the grep worker (`src/server/grep-scan.ts`), MCP `read_file`, the indexer ignore chain (`src/config/ignore-service.ts`) and the dot-directory filter (`src/core/ingestion/utils/include-dot-dirs.ts`) all call the same predicates, so a credential file hidden from indexing can no longer be re-read through another surface. `.env.example`-style templates stay readable as templates but are still excluded from the index by the pre-existing ignore list. `GITNEXUS_ALLOW_SECRET_READS=1` remains the only opt-out.
   - **Canonical path containment (`SEC-001`)**: `gitnexus/src/core/security/path-containment.ts` resolves both the workspace root and the requested path with `fs.realpath` and rejects any canonical path that leaves the workspace. `POST /api/analyze` now goes through the exported `resolveAnalyzeRepoPath()` helper, returns `403` for escapes and `400` for missing or unresolvable paths, and passes the canonical path to the analysis job. The filesystem walker keeps its per-entry realpath re-check, and `grep` re-validates every canonical file path immediately before reading, so a symlink retargeted after the entry check cannot be followed.
   - **Ignore-file precedence (`SEC-002`)**: `.gitnexusignore` negations (`!.env`, `!.ssh/`) can no longer re-enable credential files or directories while secret reads are disabled.
   - **MCP repository least privilege (`SEC-003`)**: registry path keys are canonicalised (`realpathSync.native`, case-folded on win32), CWD scoping now requires the CWD to *be* the repository root (ancestor and descendant auto-grants removed), absolute specifiers are canonicalised before matching, and a restricted policy with zero allowed repositories fails closed instead of silently falling back to the global registry. `list_repos`, tool repository resolution and `gitnexus://repo/...` resources all share the same policy object.
   - **Air-gap setup (`SEC-004`)**: `gitnexus setup --air-gap` (or `GITNEXUS_AIR_GAP=1`/`true`) requires a locally installed binary and prints offline installation guidance instead of emitting an `npx -y gitnexus@...` MCP command. Because the Claude Code hook adapter is no longer shipped, setup also refuses to register legacy editors at all — there is no hook path left that could spawn `npx`.
   - **Private storage directories (`SEC-006`)**: `gitnexus/src/storage/private-dirs.ts` provides `ensurePrivateDirectory()`, which creates directories with `0700`, re-validates existing ones, refuses symlinks and non-directories, skips directories owned by another uid and only chmods when group/other bits are set. It is applied to the global registry, the per-repository metadata directory and the CLI config directory; sensitive config files remain `0600`. Windows is skipped and relies on the user-profile ACLs.
   - **Supply chain (`SEC-005`)**: `@scarf/scarf` is removed from `package.json` *and* `package-lock.json`; the verification run asserts `npm ls @scarf/scarf --all` is empty after a clean `npm ci`.

### Verifying the remediation

Inside the Podman test harness (never on the host):

```bash
podman compose --profile test run --rm test
```

The `test` service overlays the fork into a container-local build volume and runs `scripts/run-security-tests.sh`, which performs a clean `npm ci`, asserts `@scarf/scarf` is gone, typechecks `src` and the tests, then runs `security-sensitive-files`, `security-containment`, `security-grep-scan`, `security-ignore-secrets`, `security-private-dirs`, `setup-airgap`, `api-file-route`, `mcp-repository-policy`, `setup` and `ignore-service`, followed by the `gitnexus-opencode` plugin build and its 179-test suite. The last verified run reported `Test Files 10 passed (10)`, `Tests 328 passed | 1 skipped (329)` for GitNexus and `179 passed / 0 failed` for the plugin; the only skip is the Windows-junction test, which is inert on Linux.
