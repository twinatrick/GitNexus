# GitNexus (Hardened OpenCode Security Fork)

This fork of `abhigyanpatwari/GitNexus` (`v1.6.12`) implements the security and OpenCode compatibility hardening documented in `ADR-0001`, `ADR-0002`, and `ADR-0003`:

1. **Zero Install/Runtime Telemetry & Egress**:
   - Removed `@scarf/scarf` from `gitnexus/package.json`.
   - Disabled implicit background `registry.npmjs.org` update checks in CLI and `serve` modes unless `GITNEXUS_ENABLE_UPDATE_CHECK=1` is explicitly set.
2. **Secure-by-Default MCP Policy (`ADR-0002`)**:
   - `GITNEXUS_MCP_READ_ONLY` defaults to `true` (disables raw `cypher`, `refresh_index`, `group_*`, and forces `rename` to preview-only `dry_run: true`). Set `GITNEXUS_MCP_READ_ONLY=0` only when write tools are intentionally required.
   - `createMcpRepositoryPolicy` automatically scopes accessible repositories to the active workspace (`process.cwd()`) rather than exposing all historic repositories in `~/.gitnexus/registry.json`.
3. **Out-of-Tree Symlink Containment in `gitnexus analyze`**:
   - `filesystem-walker.ts` now resolves `fs.realpath` for every candidate file and rejects any symlink escaping `repoPath`, preventing external sensitive files from being indexed into LadybugDB.
4. **Local HTTP API (`gitnexus serve`) Hardening (`ADR-0003`)**:
   - Removed `Access-Control-Allow-Private-Network: true` and stripped RFC 1918 LAN / `vercel.app` CORS origins. Only strict loopback origins (`localhost` / `127.0.0.1`) are allowed.
5. **Untrusted Repository Metadata Boundary**:
   - Wrapped `augment` and MCP `getNextStepHint` outputs in `<untrusted_repo_metadata>` tags after neutralizing XML/control characters and fake `[GitNexus]` prefixes.
