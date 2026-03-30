# ADO Security Issue Resolution Tracker

Automates triage of security vulnerability issues tracked as Azure DevOps (ADO) work items for **Langchain4j** and **Spring AI**. The tool parses vulnerability descriptions (e.g., from Snyk, Dependabot, or similar scanners), checks whether each vulnerability has been resolved by dependency updates in the latest stable releases, produces a human-reviewable markdown report, and — after approval — bulk-updates work items in ADO.

---

## Prerequisites

- **Python 3.10+** (via a virtual environment — see Setup)
- **Azure CLI** with the **Azure DevOps extension** installed
- A **GitHub token** (recommended to avoid API rate limits)

### Azure CLI Setup

1. Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
2. Add the Azure DevOps extension:
   ```bash
   az extension add --name azure-devops
   ```
3. Sign in interactively. **This is critical** — ADO requires a browser-based interactive login to "materialize" your identity in the organization:
   ```bash
   az login
   ```
   > **Note:** A raw bearer token (`az account get-access-token --resource ...`) may return 403 even after `az login`. The tool uses `az boards` CLI commands instead of raw REST, which handles auth correctly through the Azure CLI's internal token management.

4. Set defaults for your organization and project:
   ```bash
   az devops configure --defaults organization=https://dev.azure.com/YOUR_ORG project=YOUR_PROJECT
   ```

5. Verify access:
   ```bash
   az boards query --id YOUR_QUERY_GUID --output table
   ```

### Troubleshooting ADO Access

| Error | Cause | Fix |
|-------|-------|-----|
| `Identity ... has not been materialized` | First-time login to this ADO org | Run `az login` and complete the browser flow |
| `403 The requested operation is not allowed` | Bearer token doesn't have ADO permissions | Use `az boards` commands instead of raw REST (the tool handles this) |
| `unrecognized arguments: --project` | Wrong CLI syntax for `az boards work-item show` | The tool omits `--project` for work-item commands (it's not supported there) |

---

## Setup

```bash
# Create a virtual environment (required on WSL / externally-managed Python)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set GITHUB_TOKEN
```

Set `GITHUB_TOKEN` in `.env` to avoid GitHub API rate limits. Get one from [GitHub Settings > Personal Access Tokens](https://github.com/settings/personal-access-tokens) — only the default **public repo read** scope is needed, no write permissions.

The token is used for two GitHub REST API operations during the `analyze` phase:
- **Tag listing** — to find the release tag (e.g., `v1.1.4`, `1.12.2`) for each target project
- **POM file fetching** — to download all `pom.xml` files from that release tag's file tree (177 files for Spring AI, 107 for Langchain4j)

Without a token: 60 requests/hour (will hit the limit on the first run). With a token: 5,000 requests/hour.

---

## Usage

Always activate the virtual environment first:

```bash
source .venv/bin/activate
```

### Phase 1 — Analyze (read-only, safe)

```bash
python ado_issue_tracker.py analyze
```

This:
1. Runs the saved ADO query via `az boards query`
2. Fetches each work item's full details via `az boards work-item show`
3. Parses vulnerability descriptions from each work item (supports Snyk format and similar scanners)
4. Fetches `pom.xml` files from GitHub release tags for Langchain4j and Spring AI
5. Compares vulnerable dependency versions against managed/declared versions
6. Writes `analysis-report.md` (human-readable) and `analysis-report.json` (machine-readable)

**Options:**
```bash
python ado_issue_tracker.py analyze \
  --org YOUR_ORG \
  --project YOUR_PROJECT \
  --query-id YOUR_QUERY_GUID \
  --targets "langchain4j:1.12.2,spring-ai:1.1.4" \
  --output analysis-report.md \
  --github-token ghp_YOURTOKEN \
  --no-cache                # Force re-fetch of dependency data
```

### Analyzing Specific Work Items

Instead of running the full query, you can analyze one or more specific work items by ID:

```bash
# Single work item
python ado_issue_tracker.py analyze --workitem 204397

# Multiple work items (comma-separated)
python ado_issue_tracker.py analyze --workitem 204397,204455
```

When using `--workitem`, the tool:
- Skips the ADO query and fetches only the specified item(s)
- Bypasses the state/priority filter (analyzes regardless of current state)
- Is much faster since it only fetches 1-2 items instead of 90+

This is useful for:
- Testing a single complex work item with multiple vulnerabilities
- Re-analyzing an item after changes
- Debugging parser issues on specific descriptions

### Phase 2 — Update (writes to ADO, after reviewing the report)

```bash
python ado_issue_tracker.py update --report analysis-report.md
```

For each resolved work item, the tool:
- Sets the **State** to `Security Issue Resolved`
- **Assigns** the work item to the user specified by `--assign-to` or `ADO_ASSIGN_TO`
- Adds a rich **HTML Discussion comment** with:
  - Vulnerability title, severity, and status
  - Current dependency version (or confirmation that the dependency was removed)
  - Links to the relevant `pom.xml` and project release on GitHub
  - Link to the security advisory (e.g., Snyk URL)
  - Credit to `java-ai-issue-tracker-ado` as the auto-resolution tool

**Options:**
```bash
python ado_issue_tracker.py update \
  --report analysis-report.md \
  --assign-to "Your Name <you@example.com>" \
  --dry-run         # Preview without making changes
  --confirm         # Skip interactive prompt (for scripting)
```

To update only specific work items from the report:

```bash
python ado_issue_tracker.py update --workitem 204397 --report analysis-report.md
```

**Interactive prompt options:**
- `y` — Update all resolved items
- `N` — Cancel, no changes
- `select` — Pick specific work items by ID

---

## How It Works

### Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Azure CLI   │     │  GitHub API       │     │  Maven Central API  │
│  az boards   │     │  (pom.xml fetch)  │     │  (fallback lookup)  │
└──────┬───────┘     └────────┬──────────┘     └──────────┬──────────┘
       │                      │                           │
       ▼                      ▼                           ▼
┌─────────────┐     ┌──────────────────┐     ┌────────────────────────┐
│ ado_client   │     │ dependency_      │     │ issue_parser           │
│ .py          │     │ resolver.py      │     │ .py                    │
│              │     │                  │     │ Parse vulnerability    │
│ Query + fetch│     │ Fetch POMs from  │     │ descriptions           │
│ work items   │     │ release tags,    │     │ Detect parent project  │
│ Update state │     │ resolve versions │     │ from ADO field         │
└──────┬───────┘     └────────┬──────────┘     └──────────┬────────────┘
       │                      │                           │
       └──────────────────────┼───────────────────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ ado_issue_tracker.py   │
                   │ (CLI entry point)     │
                   │                       │
                   │ Phase 1: analyze      │
                   │ Phase 2: update       │
                   └──────────┬────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ report_generator.py   │
                   │                       │
                   │ Markdown report       │
                   │ JSON sidecar          │
                   └───────────────────────┘
```

### ADO Integration Details

The tool uses the **Azure CLI `az boards` commands** rather than raw REST API calls. This was chosen because:

- `az login` handles Entra ID authentication via browser-based interactive flow
- The `az boards` commands use the CLI's internal token management, which avoids the 403 errors that occur with raw bearer tokens on some ADO organizations
- No Personal Access Token (PAT) is needed when using `az login`

**Commands used:**

| Operation | Command |
|-----------|---------|
| Run saved query | `az boards query --id {query_id} --project {project} --org {org_url}` |
| Fetch work item | `az boards work-item show --id {id} --expand all` |
| Update work item | `az boards work-item update --id {id} --state "Security Issue Resolved" --fields "System.AssignedTo=..." --discussion "..."` |

> **Note:** `az boards work-item show` and `update` do not accept `--project` — the project is inferred from the work item ID. The tool handles this automatically.

### Dependency Resolution

For each target project (Langchain4j 1.12.2, Spring AI 1.1.4), the tool:

1. **Lists tags** via GitHub API to find the release tag (e.g., `1.12.2`, `v1.1.4`)
2. **Fetches the full file tree** at that tag
3. **Downloads all `pom.xml` files** (107 for Langchain4j, 177 for Spring AI)
4. **Parses** `<dependencyManagement>`, `<dependencies>`, and `<properties>` sections
5. **Resolves** `${property}` placeholders by walking parent POMs
6. **Caches** the resolved data to `dependency-cache/` (7-day TTL) to avoid re-fetching
7. **Falls back** to Maven Central Search API if a version can't be resolved from POMs

### Vulnerability Classification

| Category | Meaning |\n|----------|---------|
| `RESOLVED_BY_DEPENDENCY_UPDATE` | Dependency updated to a version >= the fix version in the project's POMs |
| `RESOLVED_TRANSITIVE_UPDATE` | Transitive dependency — not directly managed in POMs but latest version on Maven Central is >= fix version |
| `RESOLVED_DEPENDENCY_REMOVED` | Vulnerable dependency no longer found in the project or on Maven Central |
| `UNRESOLVED_DEPENDENCY` | Dependency still present at a vulnerable version |
| `NON_DEPENDENCY_ISSUE` | Issue is not related to a dependency version |
| `PARSE_ERROR` | Could not parse the vulnerability description (HTML encoding, unsupported format, etc.) |

### Parent Project Detection

Each work item has a **Project** field set to either `SpringAI` or `LangChain4j`. The tool reads this field to determine which project's dependency tree to check against. This field should be visible as a column in your saved ADO query.

---

## Configuration

All parameters can be set via CLI arguments, environment variables, or a `.env` file:

| Setting | CLI Argument | Env Variable | Default |
|---------|-------------|-------------|---------|
| ADO Organization | `--org` | `ADO_ORG` | *(required)* |
| ADO Project | `--project` | `ADO_PROJECT` | *(required)* |
| ADO Query ID | `--query-id` | `ADO_QUERY_ID` | *(required unless --workitem)* |
| Target versions | `--targets` | `TARGETS` | `langchain4j:1.12.2,spring-ai:1.1.4` |
| GitHub token | `--github-token` | `GITHUB_TOKEN` | *(none)* |
| Assign to | `--assign-to` | `ADO_ASSIGN_TO` | *(required for update)* |
| Work item ID(s) | `--workitem` | — | *(none — uses query)* |
| PAT (fallback) | — | `ADO_PAT` | *(none)* |

---

## Output Files

| File | Phase | Purpose |
|------|-------|---------|
| `analysis-report.md` | Analyze | Human-reviewable report grouped by priority |
| `analysis-report.json` | Analyze | Machine-readable data (used by update phase) |
| `update-log.md` | Update | Record of all ADO changes made |
| `ado_issue_tracker.log` | Both | Detailed debug/info log |
| `dependency-cache/` | Analyze | Cached POM data (avoids re-fetching from GitHub) |

---

## File Structure

```
java-ai-issue-tracker-ado/
├── ado_issue_tracker.py      # CLI entry point (analyze + update commands)
├── ado_client.py            # ADO REST/CLI client (auth, query, update)
├── issue_parser.py           # Vulnerability description parser + project detection
├── dependency_resolver.py   # GitHub POM fetcher + Maven version resolver
├── report_generator.py      # Markdown + JSON report generation
├── requirements.txt         # Python dependencies
├── .env.example             # Configuration template
├── .gitignore
├── README.md
├── prompt v1.md             # Original requirements
└── prompt v2.md             # Detailed design specification
```
