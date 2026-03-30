"""Generate and parse the markdown analysis report + JSON sidecar."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from issue_parser import WorkItemAnalysis

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

_CATEGORY_LABELS = {
    "RESOLVED_BY_DEPENDENCY_UPDATE": "Resolved — Dependency Updated",
    "RESOLVED_DEPENDENCY_REMOVED": "Resolved — Dependency Removed from Project",
    "RESOLVED_TRANSITIVE_UPDATE": "Resolved — Transitive Dependency Updated",
    "UNRESOLVED_DEPENDENCY": "Unresolved — Dependency Still Vulnerable",
    "NON_DEPENDENCY_ISSUE": "Flagged — Not a Dependency Issue",
    "PARSE_ERROR": "Parse Error — Manual Review Required",
}


def generate_report(
    results: list[WorkItemAnalysis],
    query_url: str,
    output_path: str,
    assign_to: str = "",
    target_state: str = "Security Issue Resolved",
) -> str:
    """Write the markdown report and a JSON sidecar. Returns the JSON path."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md_path = Path(output_path)
    json_path = md_path.with_suffix(".json")

    # Categorize
    resolved = [r for r in results if r.is_resolved]
    unresolved = [
        r
        for r in results
        if not r.is_resolved and r.overall_category == "UNRESOLVED_DEPENDENCY"
    ]
    non_dep = [
        r
        for r in results
        if r.overall_category == "NON_DEPENDENCY_ISSUE"
    ]
    parse_err = [
        r
        for r in results
        if r.overall_category == "PARSE_ERROR"
    ]

    lines: list[str] = []
    _w = lines.append

    _w(f"# ADO Security Issue Resolution Report")
    _w(f"Generated: {now}")
    _w(f"Query: {query_url}")
    _w("")
    _w("## Summary")
    _w(f"- Total work items analyzed: {len(results)}")
    _w(f"- Resolved (will be updated): {len(resolved)}")
    _w(f"- Unresolved (requires attention): {len(unresolved)}")
    _w(f"- Non-dependency issues (flagged): {len(non_dep)}")
    _w(f"- Parse errors (manual review): {len(parse_err)}")
    _w("")
    if resolved:
        _w("## Planned ADO Changes for Resolved Items")
        _w("")
        _w("When the `update` command is run, the following changes will be applied to each resolved work item:")
        _w("")
        _w("| Field | Current Value | New Value |")
        _w("|-------|--------------|-----------|")
        _w(f"| **State** (`System.State`) | To Do | {target_state} |")
        _w(f"| **Assigned To** (`System.AssignedTo`) | *(unassigned)* | {assign_to} |")
        _w(f"| **Resolved Date** (`Microsoft.VSTS.Common.ResolvedDate`) | *(empty)* | *Auto-set by ADO to {today}* |")
        _w(f"| **Resolved By** (`Microsoft.VSTS.Common.ResolvedBy`) | *(empty)* | *Auto-set by ADO to authenticated user* |")
        _w(f"| **Discussion** | *(empty)* | Rich HTML comment with resolution details (see below) |")
        _w("")
        _w("> **Note:** `Resolved Date` and `Resolved By` are automatically populated by Azure DevOps")
        _w("> when the State transitions to a resolved category. They cannot be set manually.")
        _w("")

    # Group by priority
    priorities = sorted({r.priority for r in results})
    for pri in priorities:
        pri_results = [r for r in results if r.priority == pri]
        _w(f"## Priority {pri}")
        _w("")

        # -- Unresolved -------------------------------------------------------
        pri_unresolved = [r for r in pri_results if r in unresolved]
        _w("### Unresolved Issues")
        if pri_unresolved:
            _w(
                "| ADO ID | Title | Severity | Vulnerable Package "
                "| Current Version | Fix Version | Category | Parent Project | Action |"
            )
            _w(
                "|--------|-------|----------|-------------------"
                "|-----------------|-------------|----------|----------------|--------|"
            )
            for r in _sort_by_severity(pri_unresolved):
                for vuln, cat, detail, *_ in r.results:
                    if cat == "UNRESOLVED_DEPENDENCY":
                        _w(
                            f"| {r.work_item_id} | {vuln.title} | {vuln.severity} "
                            f"| {vuln.vulnerable_package} | {vuln.vulnerable_version} "
                            f"| {vuln.fix_version} | {cat} | {r.parent_project} "
                            f"| Needs fix |"
                        )
        else:
            _w("*None*")
        _w("")

        # -- Non-dependency ---------------------------------------------------
        pri_nondep = [r for r in pri_results if r in non_dep]
        _w("### Non-Dependency Issues (Flagged)")
        if pri_nondep:
            _w(
                "| ADO ID | Title | Severity | Description Excerpt "
                "| Category | Action |"
            )
            _w(
                "|--------|-------|----------|-------------------"
                "|----------|--------|"
            )
            for r in pri_nondep:
                excerpt = r.raw_description[:200].replace("|", " ")
                for vuln, cat, _detail, *_ in r.results:
                    _w(
                        f"| {r.work_item_id} | {vuln.title} | {vuln.severity} "
                        f"| {excerpt} | {cat} | Investigate |"
                    )
        else:
            _w("*None*")
        _w("")

        # -- Resolved ---------------------------------------------------------
        pri_resolved = [r for r in pri_results if r in resolved]
        _w("### Resolved Issues (Will Be Marked 'Security Issue Resolved')")
        if pri_resolved:
            _w(
                "| ADO ID | Title | Severity | Vulnerable Package "
                "| Fixed Version | Category | Parent Project | Resolution Detail |"
            )
            _w(
                "|--------|-------|----------|-------------------"
                "|---------------|----------|----------------|-------------------|"
            )
            for r in _sort_by_severity(pri_resolved):
                for vuln, cat, detail, *_ in r.results:
                    _w(
                        f"| {r.work_item_id} | {vuln.title} | {vuln.severity} "
                        f"| {vuln.vulnerable_package} | {vuln.fix_version} "
                        f"| {cat} | {r.parent_project} | {detail} |"
                    )
            _w("")
            # Per-item planned changes detail
            _w("#### Planned Discussion Comments")
            _w("")
            for r in _sort_by_severity(pri_resolved):
                _w(f"<details>")
                _w(f"<summary><strong>ADO #{r.work_item_id}</strong> — {r.work_item_title}</summary>")
                _w(f"")
                _w(f"**Fields to update:**")
                _w(f"- `System.State`: To Do → **{target_state}**")
                _w(f"- `System.AssignedTo`: → **{assign_to}**")
                _w(f"")
                _w(f"**Discussion comment that will be added:**")
                _w(f"")
                for vuln, cat, detail, *extra_list in r.results:
                    extra = extra_list[0] if extra_list and isinstance(extra_list[0], dict) else {}
                    cat_label = _CATEGORY_LABELS.get(cat, cat)
                    current_ver = extra.get("current_version", "")
                    project_url = extra.get("project_url", "")
                    pom_url = extra.get("pom_url", "")
                    _w(f"> **{vuln.title}** ({vuln.severity} Severity)")
                    _w(f"> - Status: {cat_label}")
                    if current_ver:
                        _w(f"> - Package: `{vuln.vulnerable_package}@{vuln.vulnerable_version}` is now `{current_ver}` (fix version: `{vuln.fix_version}`)")
                        _w(f"> - Dependency **updated** in {r.parent_project} dependency tree")
                    elif cat == "RESOLVED_DEPENDENCY_REMOVED":
                        _w(f"> - Package: `{vuln.vulnerable_package}@{vuln.vulnerable_version}` → fix `{vuln.fix_version}`")
                        _w(f"> - Dependency **removed** from {r.parent_project} dependency tree")
                    else:
                        _w(f"> - Package: `{vuln.vulnerable_package}@{vuln.vulnerable_version}` → fix `{vuln.fix_version}`")
                    if vuln.dependency_chain:
                        _w(f"> - Original chain: `{vuln.dependency_chain}`")
                    if vuln.snyk_url:
                        _w(f"> - Advisory: {vuln.snyk_url}")
                    if project_url:
                        _w(f"> - Project release: {project_url}")
                    if pom_url:
                        _w(f"> - Relevant pom.xml: {pom_url}")
                    _w(f"> - Detail: {detail}")
                    _w(f">")
                _w(f"")
                _w(f"</details>")
                _w(f"")
        else:
            _w("*None*")
        _w("")

        # -- Parse errors -----------------------------------------------------
        pri_errors = [r for r in pri_results if r in parse_err]
        _w("### Parse Errors (Manual Review)")
        if pri_errors:
            _w("| ADO ID | Title | Raw Description (first 200 chars) |")
            _w("|--------|-------|------------------------------------|")
            for r in pri_errors:
                excerpt = r.raw_description[:200].replace("|", " ").replace("\n", " ")
                _w(f"| {r.work_item_id} | {r.work_item_title} | {excerpt} |")
        else:
            _w("*None*")
        _w("")

    # Write markdown
    md_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Report written to %s", md_path)

    # Write JSON sidecar for Phase 2
    json_data = _to_json(results)
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    logger.info("Analysis data written to %s", json_path)

    return str(json_path)


def load_analysis_data(json_path: str) -> list[dict]:
    """Load the JSON sidecar produced by Phase 1."""
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    return data.get("work_items", [])


def get_resolved_items(json_path: str) -> list[dict]:
    """Return only the resolved work items from the analysis data."""
    items = load_analysis_data(json_path)
    return [i for i in items if i.get("is_resolved")]


# -- Helpers ------------------------------------------------------------------


def _sort_by_severity(items: list[WorkItemAnalysis]) -> list[WorkItemAnalysis]:
    """Sort by highest severity vulnerability in each work item."""

    def _key(r: WorkItemAnalysis) -> int:
        if r.results:
            return min(
                SEVERITY_ORDER.get(v.severity, 99) for v, _c, _d, *_ in r.results
            )
        return 99

    return sorted(items, key=_key)


def _to_json(results: list[WorkItemAnalysis]) -> dict:
    items = []
    for r in results:
        vulns = []
        for entry in r.results:
            vuln = entry[0]
            cat = entry[1]
            detail = entry[2]
            extra = entry[3] if len(entry) > 3 else {}
            vulns.append(
                {
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "snyk_url": vuln.snyk_url,
                    "vulnerable_package": vuln.vulnerable_package,
                    "vulnerable_version": vuln.vulnerable_version,
                    "fix_version": vuln.fix_version,
                    "dependency_chain": vuln.dependency_chain,
                    "root_dependency": vuln.root_dependency,
                    "category": cat,
                    "detail": detail,
                    "extra_info": extra if isinstance(extra, dict) else {},
                }
            )
        items.append(
            {
                "work_item_id": r.work_item_id,
                "work_item_title": r.work_item_title,
                "priority": r.priority,
                "parent_project": r.parent_project,
                "overall_category": r.overall_category,
                "is_resolved": r.is_resolved,
                "vulnerabilities": vulns,
            }
        )
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "work_items": items,
    }
