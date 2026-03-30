#!/usr/bin/env python3
"""
ADO Security Issue Resolution Tracker

Phase 1 (analyze): Fetch ADO work items, check security vulnerabilities against
    Langchain4j / Spring AI dependency trees, produce a markdown report.
Phase 2 (update):  After human review, mark resolved items as Done in ADO.

Usage:
    python ado_issue_tracker.py analyze [options]
    python ado_issue_tracker.py update  [options]

See --help for full option list.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from ado_client import AdoClient
from dependency_resolver import DependencyResolver
from report_generator import generate_report, get_resolved_items
from issue_parser import (
    WorkItemAnalysis,
    detect_parent_project,
    parse_issue_description,
)

load_dotenv()

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

# Target project registry: field_value -> (github_owner, github_repo)
TARGET_PROJECTS: dict[str, tuple[str, str]] = {
    "langchain4j": ("langchain4j", "langchain4j"),
    "spring-ai": ("spring-projects", "spring-ai"),
}

# Category priority for determining overall work-item status
# Lower number = worse (keeps the item unresolved)
_CAT_PRIORITY = {
    "PARSE_ERROR": 0,
    "NON_DEPENDENCY_ISSUE": 1,
    "UNRESOLVED_DEPENDENCY": 2,
    "RESOLVED_DEPENDENCY_REMOVED": 10,
    "RESOLVED_BY_DEPENDENCY_UPDATE": 10,
    "RESOLVED_TRANSITIVE_UPDATE": 10,
}

RESOLVED_CATEGORIES = {"RESOLVED_BY_DEPENDENCY_UPDATE", "RESOLVED_DEPENDENCY_REMOVED", "RESOLVED_TRANSITIVE_UPDATE"}


# =============================================================================
# Phase 1 — Analyze
# =============================================================================


def cmd_analyze(args: argparse.Namespace) -> None:
    ado = AdoClient(args.org, args.project, pat=args.pat)
    resolver = DependencyResolver(
        cache_dir=args.cache_dir,
        cache_ttl_days=args.cache_ttl,
        github_token=args.github_token,
        no_cache=args.no_cache,
    )
    targets = _parse_targets(args.targets)

    # 1. Fetch work items — single item or full query
    if args.workitem:
        wi_ids = [int(x.strip()) for x in args.workitem.split(",")]
        logging.info("Fetching %d specific work item(s): %s", len(wi_ids), wi_ids)
        work_items = ado.get_work_items(wi_ids)
    else:
        logging.info("Running ADO query %s ...", args.query_id)
        ids = ado.run_query(args.query_id)
        if not ids:
            logging.warning("Query returned 0 work items — nothing to analyze.")
            return
        logging.info("Query returned %d work item IDs", len(ids))
        work_items = ado.get_work_items(ids)
    logging.info("Fetched %d work items with full details", len(work_items))

    # 2. Pre-resolve dependency trees for target projects
    dep_maps: dict[str, DependencyResolver] = {}
    project_deps_cache: dict[str, object] = {}
    for name, (owner, repo) in TARGET_PROJECTS.items():
        version = targets.get(name)
        if not version:
            continue
        try:
            project_deps_cache[name] = resolver.resolve_project(owner, repo, version)
        except Exception as e:
            logging.error("Failed to resolve %s %s: %s", name, version, e)

    # 3. Analyze each work item
    results: list[WorkItemAnalysis] = []
    for wi in work_items:
        fields = wi.get("fields", {})
        wi_id = wi["id"]
        title = fields.get("System.Title", f"Work Item {wi_id}")
        priority = fields.get("Microsoft.VSTS.Common.Priority", 99)
        state = fields.get("System.State", "")
        wi_type = fields.get("System.WorkItemType", "")
        description = fields.get("System.Description", "")

        # Filter: only "To Do" Issues with priority 1 (skip when --workitem is used)
        if not args.workitem and (state != "To Do" or priority != 1):
            logging.debug("Skipping %d (state=%s, priority=%s)", wi_id, state, priority)
            continue

        analysis = WorkItemAnalysis(
            work_item_id=wi_id,
            work_item_title=title,
            priority=priority,
            parent_project="Unknown",
            raw_description=description[:500],
        )

        # Detect parent project
        proj_display, proj_owner, proj_repo = detect_parent_project(
            fields, project_field=args.project_field
        )
        analysis.parent_project = proj_display

        if proj_display == "Unknown":
            analysis.overall_category = "PARSE_ERROR"
            analysis.results.append(
                (
                    _dummy_vuln("Unknown project"),
                    "PARSE_ERROR",
                    "Could not determine parent project from work item fields",
                    {},
                )
            )
            results.append(analysis)
            continue

        # Find matching target
        target_key = None
        for key, (owner, repo) in TARGET_PROJECTS.items():
            if owner == proj_owner and repo == proj_repo:
                target_key = key
                break

        if target_key not in project_deps_cache:
            analysis.overall_category = "PARSE_ERROR"
            analysis.results.append(
                (
                    _dummy_vuln("No dep data"),
                    "PARSE_ERROR",
                    f"Dependency data not available for {proj_display}",
                    {},
                )
            )
            results.append(analysis)
            continue

        pdeps = project_deps_cache[target_key]

        # Parse vulnerability description
        vulns = parse_issue_description(description)
        if not vulns:
            analysis.overall_category = "PARSE_ERROR"
            analysis.results.append(
                (
                    _dummy_vuln(title),
                    "PARSE_ERROR",
                    "Could not parse vulnerability from description",
                    {},
                )
            )
            results.append(analysis)
            continue

        analysis.vulnerabilities = vulns

        # Check each vulnerability
        worst_priority = 99
        for vuln in vulns:
            cat, detail, extra = resolver.check_vulnerability(
                pdeps, vuln.vulnerable_package, vuln.fix_version,
                vulnerable_version=vuln.vulnerable_version,
            )
            analysis.results.append((vuln, cat, detail, extra))
            cat_pri = _CAT_PRIORITY.get(cat, 5)
            if cat_pri < worst_priority:
                worst_priority = cat_pri
                analysis.overall_category = cat

        # A work item is resolved only if ALL its vulnerabilities are resolved
        analysis.is_resolved = all(
            cat in RESOLVED_CATEGORIES for _, cat, _, _ in analysis.results
        )
        if analysis.is_resolved:
            analysis.overall_category = analysis.results[0][1]

        results.append(analysis)

    if not results:
        logging.warning("No qualifying work items (state=To Do, priority=1).")
        return

    # 4. Generate report
    query_url = (
        f"https://dev.azure.com/{args.org}/{args.project}/"
        f"_queries/query/{args.query_id}/"
    )
    json_path = generate_report(
        results, query_url, args.output,
        assign_to=args.assign_to,
        target_state=args.target_state,
    )
    _print_summary(results, args.output, json_path)


# =============================================================================
# Phase 2 — Update
# =============================================================================


def cmd_update(args: argparse.Namespace) -> None:
    json_path = Path(args.report).with_suffix(".json")
    if not json_path.exists():
        logging.error(
            "Analysis data file not found: %s  (run 'analyze' first)", json_path
        )
        sys.exit(1)

    resolved = get_resolved_items(str(json_path))

    # Filter to specific work item(s) if requested
    if hasattr(args, 'workitem') and args.workitem:
        wi_ids = {int(x.strip()) for x in args.workitem.split(",")}
        resolved = [r for r in resolved if r["work_item_id"] in wi_ids]

    if not resolved:
        print("No resolved work items found in the report. Nothing to update.")
        return

    # Show summary
    print(f"\n{'='*60}")
    print(f" ADO Snyk Issue Tracker — Update Phase")
    print(f"{'='*60}")
    print(f" Resolved work items ready to update: {len(resolved)}")
    for item in resolved:
        vulns = item.get("vulnerabilities", [])
        vuln_summary = ", ".join(v["vulnerable_package"] for v in vulns[:3])
        if len(vulns) > 3:
            vuln_summary += f" (+{len(vulns)-3} more)"
        print(f"   [{item['work_item_id']}] {item['work_item_title']}")
        print(f"      Project: {item['parent_project']}  |  Vulns: {vuln_summary}")
    print()

    if args.dry_run:
        print("[DRY RUN] No changes will be made.")
        return

    # Prompt
    if not args.confirm:
        choice = input(
            f"Update {len(resolved)} work items? [y/N/select]: "
        ).strip().lower()
        if choice == "n" or choice == "":
            print("Cancelled. No changes made.")
            return
        elif choice == "select":
            selected_ids = _interactive_select(resolved)
            if not selected_ids:
                print("No items selected. Cancelled.")
                return
            resolved = [r for r in resolved if r["work_item_id"] in selected_ids]
        elif choice != "y":
            print("Invalid choice. Cancelled.")
            return

    # Apply updates
    ado = AdoClient(args.org, args.project, pat=args.pat)
    log_entries: list[dict] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for item in resolved:
        wi_id = item["work_item_id"]
        vulns = item.get("vulnerabilities", [])
        parent = item.get("parent_project", "Unknown")
        try:
            # Update state + assignment (no discussion yet)
            ado.update_work_item(
                wi_id,
                state=args.target_state,
                assigned_to=args.assign_to,
                discussion="",
            )

            # Post vulnerabilities in reverse order so ADO displays them
            # top-to-bottom (ADO shows newest comments first)
            for i in range(len(vulns), 0, -1):
                v = vulns[i - 1]
                vuln_comment = _build_single_vuln_comment(v, i, len(vulns), parent, now)
                ado.add_work_item_comment(wi_id, vuln_comment)
                time.sleep(0.2)

            # Post header last so it appears at the top of the discussion
            ado.add_work_item_comment(
                wi_id, _build_header_comment(len(vulns), parent, now)
            )

            log_entries.append(
                {"work_item_id": wi_id, "status": "success", "timestamp": now}
            )
            logging.info("Updated work item %d to %s (%d comments)", wi_id, args.target_state, len(vulns) + 1)
            print(f"  ✓ {wi_id} — {args.target_state} ({len(vulns)} vulnerabilities)")
            time.sleep(0.3)

        except Exception as e:
            log_entries.append(
                {
                    "work_item_id": wi_id,
                    "status": "error",
                    "error": str(e),
                    "timestamp": now,
                }
            )
            logging.error("Failed to update work item %d: %s", wi_id, e)
            print(f"  ✗ {wi_id} — FAILED: {e}")

    # Write update log
    _write_update_log(log_entries, args.org, args.project)

    successes = sum(1 for e in log_entries if e["status"] == "success")
    failures = sum(1 for e in log_entries if e["status"] == "error")
    print(f"\nDone. {successes} updated, {failures} failed.")


# =============================================================================
# Helpers
# =============================================================================


def _parse_targets(targets_str: str) -> dict[str, str]:
    """Parse --targets 'langchain4j:1.12.2,spring-ai:1.1.4' into a dict."""
    result: dict[str, str] = {}
    for pair in targets_str.split(","):
        pair = pair.strip()
        if ":" in pair:
            name, version = pair.split(":", 1)
            result[name.strip().lower()] = version.strip()
    return result


def _dummy_vuln(title: str):
    """Create a placeholder Vulnerability for parse-error items."""
    from issue_parser import Vulnerability

    return Vulnerability(
        title=title,
        severity="Unknown",
        snyk_url="",
        vulnerable_package="",
        vulnerable_version="",
        dependency_chain="",
        fix_version="",
        root_dependency="",
    )


_CATEGORY_LABELS = {
    "RESOLVED_BY_DEPENDENCY_UPDATE": "Resolved — Dependency Updated",
    "RESOLVED_DEPENDENCY_REMOVED": "Resolved — Dependency Removed from Project",
    "RESOLVED_TRANSITIVE_UPDATE": "Resolved — Transitive Dependency Updated",
    "UNRESOLVED_DEPENDENCY": "Unresolved — Dependency Still Vulnerable",
    "NON_DEPENDENCY_ISSUE": "Flagged — Not a Dependency Issue",
    "PARSE_ERROR": "Parse Error — Manual Review Required",
}


def _build_header_comment(vuln_count: int, parent_project: str, timestamp: str) -> str:
    """Build the initial summary comment posted with the state change."""
    return (
        "<h2>🔒 Security Issue Auto-Resolved</h2>"
        "<p><em>This issue was automatically analyzed and resolved by "
        "<strong>java-ai-issue-tracker-ado</strong>.</em></p>"
        f"<p><strong>{vuln_count} vulnerabilities</strong> found in "
        f"<strong>{parent_project}</strong>. "
        f"Each vulnerability is documented in a separate comment below.</p>"
        f"<p><strong>Verified:</strong> {timestamp}</p>"
        "<p><em>🤖 Auto-resolved by "
        "<a href=\"https://github.com/bbenz/java-ai-issue-tracker-ado\">"
        "java-ai-issue-tracker-ado</a> — an automated security issue triage tool "
        "for Azure DevOps.</em></p>"
    )


def _build_single_vuln_comment(
    v: dict, index: int, total: int, parent_project: str, timestamp: str
) -> str:
    """Build an HTML comment for a single vulnerability."""
    cat = v.get("category", "UNKNOWN")
    cat_label = _CATEGORY_LABELS.get(cat, cat)
    extra = v.get("extra_info", {})
    current_ver = extra.get("current_version", "")
    project_url = extra.get("project_url", "")
    pom_url = extra.get("pom_url", "")

    lines: list[str] = []
    lines.append(f"<h3>Vulnerability {index} of {total}</h3>")
    lines.append(f"<p><strong>🛡️ {v.get('title', 'Unknown')}</strong> "
                  f"({v.get('severity', 'Unknown')} Severity)</p>")
    lines.append("<table>")

    lines.append(f"<tr><td><strong>Status</strong></td>"
                  f"<td>✅ {cat_label}</td></tr>")

    lines.append(f"<tr><td><strong>Affected Package</strong></td>"
                  f"<td><code>{v.get('vulnerable_package', '')}"
                  f"@{v.get('vulnerable_version', '')}</code></td></tr>")

    lines.append(f"<tr><td><strong>Fix Version</strong></td>"
                  f"<td><code>{v.get('fix_version', '')}</code></td></tr>")

    if current_ver:
        lines.append(
            f"<tr><td><strong>Current Version in {parent_project}</strong></td>"
            f"<td><code>{current_ver}</code> "
            f"(updated from <code>{v.get('vulnerable_version', '')}</code>)"
            f"</td></tr>"
        )
    else:
        if cat == "RESOLVED_DEPENDENCY_REMOVED":
            lines.append(
                f"<tr><td><strong>Current Status in {parent_project}</strong></td>"
                f"<td>This dependency is <strong>no longer present</strong> in the "
                f"{parent_project} dependency tree.</td></tr>"
            )
        elif cat == "RESOLVED_TRANSITIVE_UPDATE":
            lines.append(
                f"<tr><td><strong>Current Status in {parent_project}</strong></td>"
                f"<td>Transitive dependency — latest version on Maven Central "
                f"is at or above the fix version.</td></tr>"
            )

    lines.append(f"<tr><td><strong>Parent Project</strong></td>"
                  f"<td>{parent_project}</td></tr>")

    if v.get("dependency_chain"):
        chain = v["dependency_chain"].replace(">", "→")
        lines.append(f"<tr><td><strong>Original Dependency Chain</strong></td>"
                      f"<td><code>{chain}</code></td></tr>")

    if v.get("snyk_url"):
        lines.append(
            f"<tr><td><strong>Security Advisory</strong></td>"
            f"<td><a href=\"{v['snyk_url']}\">{v['snyk_url']}</a></td></tr>"
        )

    if project_url:
        lines.append(
            f"<tr><td><strong>Project Release</strong></td>"
            f"<td><a href=\"{project_url}\">{project_url}</a></td></tr>"
        )

    if pom_url:
        lines.append(
            f"<tr><td><strong>Relevant pom.xml</strong></td>"
            f"<td><a href=\"{pom_url}\">{pom_url}</a></td></tr>"
        )

    lines.append("</table>")
    lines.append(f"<p><strong>Resolution Detail:</strong> {v.get('detail', '')}</p>")

    return "\n".join(lines)


def _print_summary(
    results: list[WorkItemAnalysis], report_path: str, json_path: str
) -> None:
    resolved = sum(1 for r in results if r.is_resolved)
    unresolved = sum(
        1
        for r in results
        if not r.is_resolved and r.overall_category == "UNRESOLVED_DEPENDENCY"
    )
    flagged = sum(
        1 for r in results if r.overall_category == "NON_DEPENDENCY_ISSUE"
    )
    errors = sum(1 for r in results if r.overall_category == "PARSE_ERROR")

    print(f"\n{'='*60}")
    print(f" Analysis Complete")
    print(f"{'='*60}")
    print(f" Total work items:  {len(results)}")
    print(f" Resolved:          {resolved}")
    print(f" Unresolved:        {unresolved}")
    print(f" Flagged:           {flagged}")
    print(f" Parse errors:      {errors}")
    print(f"{'='*60}")
    print(f" Report:  {report_path}")
    print(f" Data:    {json_path}")
    print(f"\nReview the report, then run:")
    print(f"  python ado_issue_tracker.py update --report {report_path}")
    print()


def _interactive_select(items: list[dict]) -> set[int]:
    """Let user pick work items by entering comma-separated IDs."""
    print("\nEnter work item IDs to update (comma-separated), or 'all':")
    for item in items:
        print(f"   {item['work_item_id']} — {item['work_item_title']}")
    raw = input("> ").strip()
    if raw.lower() == "all":
        return {i["work_item_id"] for i in items}
    try:
        return {int(x.strip()) for x in raw.split(",") if x.strip()}
    except ValueError:
        print("Invalid input.")
        return set()


def _write_update_log(entries: list[dict], org: str, project: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# ADO Snyk Issue Tracker — Update Log",
        f"Executed: {now}",
        f"Organization: {org}",
        f"Project: {project}",
        "",
        "| Work Item ID | Status | Detail |",
        "|-------------|--------|--------|",
    ]
    for e in entries:
        detail = e.get("error", "Security Issue Resolved") if e["status"] == "error" else "Security Issue Resolved"
        lines.append(f"| {e['work_item_id']} | {e['status']} | {detail} |")
    lines.append("")

    log_path = Path("update-log.md")
    log_path.write_text("\n".join(lines), encoding="utf-8")
    logging.info("Update log written to %s", log_path)


# =============================================================================
# CLI
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ado_issue_tracker",
        description="Triage security issues in Azure DevOps work items.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- analyze ---
    analyze = sub.add_parser("analyze", help="Phase 1: analyze work items (read-only)")
    analyze.add_argument(
        "--org",
        default=os.getenv("ADO_ORG", ""),
        help="ADO organization (default: $ADO_ORG)",
    )
    analyze.add_argument(
        "--project",
        default=os.getenv("ADO_PROJECT", ""),
        help="ADO project (default: $ADO_PROJECT)",
    )
    analyze.add_argument(
        "--query-id",
        default=os.getenv(
            "ADO_QUERY_ID", ""
        ),
        help="Saved ADO query GUID",
    )
    analyze.add_argument(
        "--output",
        default="analysis-report.md",
        help="Output report path (default: analysis-report.md)",
    )
    analyze.add_argument(
        "--targets",
        default=os.getenv("TARGETS", "langchain4j:1.12.2,spring-ai:1.1.4"),
        help="Target projects as 'name:version,...'",
    )
    analyze.add_argument(
        "--project-field",
        default=os.getenv("ADO_PROJECT_FIELD", ""),
        help="ADO field name holding project identifier (auto-detect if blank)",
    )
    analyze.add_argument("--pat", default=os.getenv("ADO_PAT", ""), help=argparse.SUPPRESS)
    analyze.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN", ""),
        help="GitHub token (recommended to avoid rate limits)",
    )
    analyze.add_argument(
        "--cache-dir", default="dependency-cache", help=argparse.SUPPRESS
    )
    analyze.add_argument("--cache-ttl", type=int, default=7, help=argparse.SUPPRESS)
    analyze.add_argument(
        "--no-cache", action="store_true", help="Ignore cached dependency data"
    )
    analyze.add_argument(
        "--assign-to",
        default=os.getenv("ADO_ASSIGN_TO", ""),
        help="Who resolved items will be assigned to (shown in report)",
    )
    analyze.add_argument(
        "--target-state",
        default=os.getenv("ADO_TARGET_STATE", "Security Issue Resolved"),
        help="Target state for resolved items (shown in report)",
    )
    analyze.add_argument(
        "--workitem",
        default=None,
        help="Analyze specific work item ID(s) instead of running the query (comma-separated)",
    )
    analyze.set_defaults(func=cmd_analyze)

    # --- update ---
    update = sub.add_parser("update", help="Phase 2: update ADO work items")
    update.add_argument(
        "--report",
        default="analysis-report.md",
        help="Path to the analysis report from Phase 1",
    )
    update.add_argument(
        "--org",
        default=os.getenv("ADO_ORG", ""),
        help="ADO organization",
    )
    update.add_argument(
        "--project",
        default=os.getenv("ADO_PROJECT", ""),
        help="ADO project",
    )
    update.add_argument("--pat", default=os.getenv("ADO_PAT", ""), help=argparse.SUPPRESS)
    update.add_argument(
        "--assign-to",
        default=os.getenv("ADO_ASSIGN_TO", ""),
        help="Assign resolved items to this user",
    )
    update.add_argument(
        "--target-state",
        default=os.getenv("ADO_TARGET_STATE", "Security Issue Resolved"),
        help="Target state for resolved items",
    )
    update.add_argument(
        "--workitem",
        default=None,
        help="Update only specific work item ID(s) from the report (comma-separated)",
    )
    update.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be updated without making changes",
    )
    update.add_argument(
        "--confirm",
        action="store_true",
        help="Skip interactive confirmation (use in scripts)",
    )
    update.set_defaults(func=cmd_update)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Set up logging
    log_path = "ado_issue_tracker.log"
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    args.func(args)


if __name__ == "__main__":
    main()
