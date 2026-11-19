# aivirusdb

Pre-flight security scan for AI agent projects. One command checks the parts of
a project that an agent trusts without asking:

- **MCP server configs**: `mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`
- **Agent Skills and rule files**: `SKILL.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `.cursor/rules/*.mdc`, `.claude/commands/*.md`, `.claude/agents/*.md`, `AGENTS.md`, `CLAUDE.md`,
  `GEMINI.md`, `copilot-instructions.md`, `.github/prompts/*.prompt.md`
- **Permission sets** (optional): the GitHub OAuth scopes your agent's token holds

```bash
npx aivirusdb scan .
```

## What it looks for

| Rule | Severity | Finds |
|---|---|---|
| `MCP001` | medium | MCP server package started without an exact version (can change after you approved it) |
| `MCP002` | high | Credentials written inline in an MCP config |
| `MCP003` | high | Remote MCP server over plain HTTP |
| `MCP004` | high | MCP server that is an inline shell command |
| `SKL001` | high | Instructions to read local credential files (`.env`, cloud/SSH keys, registry tokens) |
| `SKL002` | critical | Download-and-execute of remote code |
| `SKL003` | critical | Reverse-shell patterns |
| `SKL004` | critical | Sending environment variables or credential files to a remote endpoint |
| `SKL005` | high | Instructions to hide actions from the user, or to ignore earlier instructions |
| `SKL006` | high | Decoding and running an embedded payload |
| `SKL007` | high | Disabling approval prompts or sandboxing |
| `PRM-GH-001`…`005` | medium–critical | Risky GitHub scope combinations, e.g. `repo` + `workflow` |

Each finding maps to the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) (ASI
ids). That is a mapping to help triage, not a certification.

**"No known issues" means no rule or advisory matched. It is not a guarantee that a project is safe.**
The rules are heuristics: a match means a person should look.

## Options

```text
aivirusdb scan [dir] [options]

  --json                 Machine-readable JSON output (same as --format json)
  --format <format>      text | json | github (annotations + job summary)
  --fail-on <level>      critical | high | medium | low | none (default: high)
  --github-scopes <list> Comma-separated GitHub OAuth scopes the agent holds
  --api-url <url>        Override the advisory API endpoint
```

Exit codes: `0` nothing at or above `--fail-on`, `1` issues at or above it, `2` usage or runtime error.

## GitHub Action

Block pull requests that add a risky MCP server, skill or rule file. Findings appear as
annotations on the PR diff and as a table in the job summary.

```yaml
name: AIVirusDB
on: [pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - uses: nje1218-sudo/aivirusdb-cli@main   # pin to a release tag or commit SHA
        with:
          fail-on: high                          # critical | high | medium | low | none
          # github-scopes: repo,workflow         # scopes your agent's token holds
          # api-key: ${{ secrets.AIVIRUSDB_API_KEY }}  # optional advisory lookup
```

Inputs: `path` (default `.`), `fail-on` (default `high`), `github-scopes`, `api-key`.
Output: `exit-code`. The action builds the scanner from its own source, so it does not
download anything from npm at run time. In any other CI, run the CLI with
`--format github` (GitHub) or `--json`.

## Known-advisory lookup (optional)

The rules above run entirely on your machine. To also check the MCP packages in your configs
against known vulnerabilities and malicious-package reports, set an AIVirusDB API key:

```bash
export AIVIRUSDB_API_KEY=aivdb_...
npx aivirusdb scan .
```

**Only package names, ecosystems and versions are sent.** File contents, findings and paths stay
on your machine. Without a key the advisory lookup is skipped and everything else still runs.
API keys and the free monthly quota are managed from your account at
[aivirusdb.com](https://www.aivirusdb.com) (not yet open).

## Privacy and safety of the scanner itself

- No network access unless `AIVIRUSDB_API_KEY` is set, and then only to the HTTPS API endpoint.
- Only well-known file names are read; symlinks, `node_modules`, `.git` and similar folders are
  skipped; files over 1 MB are skipped.
- Excerpts in reports mask secret-looking values, so output is safe to keep in CI logs.
- No runtime dependencies.

## Development

```bash
npm install
npm test        # vitest
npm run check   # tsc --noEmit
npm run build   # dist/
```

`src/engine/` is the shared scan engine also used by the AIVirusDB API.

## Releasing

Publishing a GitHub Release whose tag is `v<version>` (matching `package.json`) runs
`.github/workflows/publish.yml`, which tests, builds and publishes to npm with provenance.
npm tries Trusted Publishing (OIDC) first: npmjs.com trusts this repository, `publish.yml` and the
`npm` environment. Until that exchange works, npm falls back to the `NPM_TOKEN` secret of the `npm`
environment; the token is removed once a publish log shows the OIDC exchange succeeding.
Provenance is attached automatically.

## License

Apache-2.0. The license covers this code; it does not grant use of the AIVirusDB name or logo.
