"""Resolve dependency versions from GitHub POMs and Maven Central."""

import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
MAVEN_CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"
NS = "{http://maven.apache.org/POM/4.0.0}"


@dataclass
class ProjectDeps:
    """Aggregated dependency information for a project release."""

    project_name: str
    version: str
    # groupId:artifactId -> resolved version
    managed_versions: dict[str, str] = field(default_factory=dict)
    direct_deps: dict[str, str] = field(default_factory=dict)
    all_declared_deps: dict[str, str] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)
    # Metadata for linking back to source
    repo_url: str = ""       # e.g. "https://github.com/spring-projects/spring-ai"
    release_tag: str = ""    # e.g. "v1.1.4"
    # groupId:artifactId -> pom.xml path that declares it
    dep_sources: dict[str, str] = field(default_factory=dict)


class DependencyResolver:
    def __init__(
        self,
        cache_dir: str = "dependency-cache",
        cache_ttl_days: int = 7,
        github_token: str | None = None,
        no_cache: bool = False,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_ttl = cache_ttl_days * 86400
        self.no_cache = no_cache
        self.session = requests.Session()
        if github_token:
            self.session.headers["Authorization"] = f"token {github_token}"
        self.session.headers["Accept"] = "application/vnd.github.v3+json"
        self.session.headers["User-Agent"] = "ado-snyk-tracker"
        self._resolved: dict[str, ProjectDeps] = {}

    # -- Public API -----------------------------------------------------------

    def resolve_project(
        self, repo_owner: str, repo_name: str, version: str
    ) -> ProjectDeps:
        """Resolve all dependency information for a project release."""
        key = f"{repo_owner}/{repo_name}:{version}"
        if key in self._resolved:
            return self._resolved[key]

        # Try cache
        cache_file = self.cache_dir / f"{repo_owner}_{repo_name}_{version}.json"
        if not self.no_cache and cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < self.cache_ttl:
                logger.info("Using cached dependency data for %s", key)
                deps = self._load_cache(cache_file, repo_owner, repo_name, version)
                self._resolved[key] = deps
                return deps

        logger.info("Resolving dependencies for %s from GitHub...", key)
        tag = self._find_release_tag(repo_owner, repo_name, version)
        if not tag:
            raise ValueError(f"Could not find release tag for {key}")

        pom_files = self._fetch_pom_files(repo_owner, repo_name, tag)
        deps = self._parse_all_poms(repo_owner, repo_name, version, pom_files)
        deps.repo_url = f"https://github.com/{repo_owner}/{repo_name}"
        deps.release_tag = tag

        # Persist cache
        self._save_cache(cache_file, deps)
        self._resolved[key] = deps
        return deps

    def check_vulnerability(
        self, project_deps: ProjectDeps, package: str, fix_version: str,
        vulnerable_version: str = "",
    ) -> tuple[str, str, dict]:
        """
        Check whether a vulnerable package is resolved in the project.
        Returns (category, detail, extra_info).
        extra_info keys: current_version, pom_path, project_url, pom_url
        """
        base_url = project_deps.repo_url
        tag = project_deps.release_tag

        def _extra(current_ver: str = "", pkg: str = "") -> dict:
            pom_path = project_deps.dep_sources.get(pkg or package, "")
            return {
                "current_version": current_ver,
                "pom_path": pom_path,
                "project_url": f"{base_url}/tree/{tag}" if base_url and tag else "",
                "pom_url": f"{base_url}/blob/{tag}/{pom_path}" if base_url and tag and pom_path else "",
            }

        # 1. Check dependencyManagement (highest priority in Maven)
        if package in project_deps.managed_versions:
            ver = project_deps.managed_versions[package]
            if ver and "${" not in ver:
                if _version_gte(ver, fix_version):
                    return (
                        "RESOLVED_BY_DEPENDENCY_UPDATE",
                        f"Managed to {ver} (fix: {fix_version}) in "
                        f"{project_deps.project_name} {project_deps.version}",
                        _extra(ver),
                    )
                return (
                    "UNRESOLVED_DEPENDENCY",
                    f"Managed version {ver} < fix version {fix_version}",
                    _extra(ver),
                )

        # 2. Check all declared dependencies
        if package in project_deps.all_declared_deps:
            ver = project_deps.all_declared_deps[package]
            if ver and "${" not in ver:
                if _version_gte(ver, fix_version):
                    return (
                        "RESOLVED_BY_DEPENDENCY_UPDATE",
                        f"Updated to {ver} (fix: {fix_version}) in "
                        f"{project_deps.project_name} {project_deps.version}",
                        _extra(ver),
                    )
                return (
                    "UNRESOLVED_DEPENDENCY",
                    f"Declared version {ver} < fix version {fix_version}",
                    _extra(ver),
                )

        # 3. Package not directly listed — check if its group is still present
        group_id = package.split(":")[0] if ":" in package else package
        has_same_group = any(
            k.startswith(f"{group_id}:")
            for k in {
                **project_deps.all_declared_deps,
                **project_deps.managed_versions,
            }
        )

        if not has_same_group:
            # Package not directly declared — likely a transitive dep.
            # Check Maven Central for the latest version to give an accurate report.
            latest = self._get_latest_maven_central_version(package)
            if latest and _version_gte(latest, fix_version):
                return (
                    "RESOLVED_TRANSITIVE_UPDATE",
                    f"{package} not directly managed in "
                    f"{project_deps.project_name} {project_deps.version} "
                    f"(transitive dependency); latest version on Maven Central "
                    f"is {latest}, which is >= fix version {fix_version}",
                    _extra(current_ver=latest),
                )
            elif latest and _version_gte(latest, vulnerable_version):
                # Maven Central has a newer version than the vulnerable one,
                # but its index may lag behind. Since the package isn't
                # directly managed in the project (transitive dep), and
                # a newer version exists, it's very likely resolved.
                return (
                    "RESOLVED_TRANSITIVE_UPDATE",
                    f"{package} not directly managed in "
                    f"{project_deps.project_name} {project_deps.version} "
                    f"(transitive dependency); latest version on Maven Central "
                    f"is {latest} (fix version: {fix_version}). "
                    f"Maven Central index may lag; fix version likely available.",
                    _extra(current_ver=latest),
                )
            elif latest:
                # Latest on Maven Central is below the vulnerable version
                return (
                    "UNRESOLVED_DEPENDENCY",
                    f"{package} latest on Maven Central is {latest}, "
                    f"which is below fix version {fix_version}",
                    _extra(current_ver=latest),
                )
            else:
                # Truly not found anywhere
                return (
                    "RESOLVED_DEPENDENCY_REMOVED",
                    f"{package} not found in "
                    f"{project_deps.project_name} {project_deps.version} "
                    f"or on Maven Central — dependency appears to have been removed",
                    _extra(),
                )

        # 4. Group present but artifact not managed — try Maven Central fallback
        return self._maven_central_fallback(package, fix_version, project_deps)

    # -- GitHub tag discovery -------------------------------------------------

    def _find_release_tag(
        self, owner: str, repo: str, version: str
    ) -> str | None:
        candidates = [
            f"v{version}",
            version,
            f"{repo}-{version}",
            f"release-{version}",
            f"{version}.RELEASE",
        ]

        tags: list[str] = []
        page = 1
        while True:
            resp = self.session.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/tags",
                params={"per_page": 100, "page": page},
                timeout=30,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            tags.extend(t["name"] for t in batch)
            if len(batch) < 100:
                break
            page += 1
            time.sleep(0.3)

        for c in candidates:
            if c in tags:
                logger.info("Found release tag: %s", c)
                return c

        for tag in tags:
            if version in tag:
                logger.info("Found release tag (fuzzy): %s", tag)
                return tag

        logger.warning("No release tag found for %s/%s %s", owner, repo, version)
        return None

    # -- POM fetching ---------------------------------------------------------

    def _fetch_pom_files(
        self, owner: str, repo: str, tag: str
    ) -> dict[str, str]:
        resp = self.session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{tag}",
            params={"recursive": "1"},
            timeout=60,
        )
        resp.raise_for_status()
        tree = resp.json()

        pom_paths = [
            item["path"]
            for item in tree.get("tree", [])
            if item["path"].endswith("pom.xml") and item["type"] == "blob"
        ]
        logger.info(
            "Found %d pom.xml files in %s/%s@%s", len(pom_paths), owner, repo, tag
        )

        pom_contents: dict[str, str] = {}
        for path in pom_paths:
            resp = self.session.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                params={"ref": tag},
                headers={"Accept": "application/vnd.github.v3.raw"},
                timeout=30,
            )
            if resp.status_code == 200:
                pom_contents[path] = resp.text
            else:
                logger.warning("Failed to fetch %s: %d", path, resp.status_code)
            time.sleep(0.1)

        return pom_contents

    # -- POM parsing ----------------------------------------------------------

    def _parse_all_poms(
        self,
        owner: str,
        repo: str,
        version: str,
        pom_files: dict[str, str],
    ) -> ProjectDeps:
        deps = ProjectDeps(project_name=f"{owner}/{repo}", version=version)

        for path, content in pom_files.items():
            try:
                root = ET.fromstring(content)
            except ET.ParseError as e:
                logger.warning("Failed to parse %s: %s", path, e)
                continue

            self._extract_properties(root, deps)
            self._extract_dependency_management(root, deps, pom_path=path)
            is_root = path == "pom.xml"
            self._extract_dependencies(root, deps, is_root=is_root, pom_path=path)

        # Resolve ${property} placeholders
        self._resolve_properties(deps)
        logger.info(
            "Resolved %d managed + %d declared deps for %s/%s %s",
            len(deps.managed_versions),
            len(deps.all_declared_deps),
            owner,
            repo,
            version,
        )
        return deps

    @staticmethod
    def _extract_properties(root: ET.Element, deps: ProjectDeps):
        for props_el in root.findall(f".//{NS}properties"):
            for child in props_el:
                tag = child.tag.replace(NS, "")
                if child.text:
                    deps.properties[tag] = child.text.strip()

        # Project and parent versions as implicit properties
        ver_el = root.find(f"{NS}version")
        if ver_el is not None and ver_el.text:
            deps.properties.setdefault("project.version", ver_el.text.strip())

        parent = root.find(f"{NS}parent")
        if parent is not None:
            pv = parent.find(f"{NS}version")
            if pv is not None and pv.text:
                deps.properties.setdefault(
                    "project.parent.version", pv.text.strip()
                )

    @staticmethod
    def _extract_dependency_management(
        root: ET.Element, deps: ProjectDeps, pom_path: str = ""
    ):
        path = f"{NS}dependencyManagement/{NS}dependencies/{NS}dependency"
        for dep in root.findall(path):
            gid = dep.findtext(f"{NS}groupId", "").strip()
            aid = dep.findtext(f"{NS}artifactId", "").strip()
            ver = dep.findtext(f"{NS}version", "").strip()
            scope = dep.findtext(f"{NS}scope", "").strip()
            dep_type = dep.findtext(f"{NS}type", "").strip()

            if not gid or not aid:
                continue

            # Skip BOM imports (type=pom, scope=import) — they are references
            # to external BOMs, not direct version pins
            if dep_type == "pom" and scope == "import":
                continue

            key = f"{gid}:{aid}"
            if ver:
                deps.managed_versions[key] = ver
                if pom_path:
                    deps.dep_sources[key] = pom_path

    @staticmethod
    def _extract_dependencies(
        root: ET.Element, deps: ProjectDeps, is_root: bool = False,
        pom_path: str = ""
    ):
        # Direct <dependencies> children of <project> (not inside dependencyManagement)
        for dep in root.findall(f"{NS}dependencies/{NS}dependency"):
            gid = dep.findtext(f"{NS}groupId", "").strip()
            aid = dep.findtext(f"{NS}artifactId", "").strip()
            ver = dep.findtext(f"{NS}version", "").strip()
            if not gid or not aid:
                continue
            key = f"{gid}:{aid}"
            if ver:
                deps.all_declared_deps[key] = ver
                if pom_path:
                    deps.dep_sources.setdefault(key, pom_path)
            if is_root and ver:
                deps.direct_deps[key] = ver

    @staticmethod
    def _resolve_properties(deps: ProjectDeps):
        prop_re = re.compile(r"\$\{([^}]+)}")

        def resolve(val: str, depth: int = 0) -> str:
            if depth > 10 or "${" not in val:
                return val

            def _sub(m: re.Match) -> str:
                return deps.properties.get(m.group(1), m.group(0))

            return resolve(prop_re.sub(_sub, val), depth + 1)

        for mapping in (
            deps.managed_versions,
            deps.all_declared_deps,
            deps.direct_deps,
        ):
            for key in mapping:
                mapping[key] = resolve(mapping[key])

    # -- Maven Central helpers --------------------------------------------------

    def _get_latest_maven_central_version(self, package: str) -> str | None:
        """Query Maven Central for the latest release version of a package."""
        parts = package.split(":")
        if len(parts) != 2:
            return None
        group_id, artifact_id = parts
        try:
            resp = self.session.get(
                MAVEN_CENTRAL_SEARCH,
                params={
                    "q": f'g:"{group_id}" AND a:"{artifact_id}"',
                    "rows": 1,
                    "wt": "json",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                if docs:
                    return docs[0].get("latestVersion", "") or docs[0].get("v", "")
        except requests.RequestException as e:
            logger.warning("Maven Central lookup failed for %s: %s", package, e)
        return None

    def _maven_central_fallback(
        self, package: str, fix_version: str, project_deps: ProjectDeps
    ) -> tuple[str, str, dict]:
        """Check Maven Central when the artifact is not directly managed."""
        base_url = project_deps.repo_url
        tag = project_deps.release_tag
        _empty_extra: dict = {
            "current_version": "",
            "pom_path": "",
            "project_url": f"{base_url}/tree/{tag}" if base_url and tag else "",
            "pom_url": "",
        }
        parts = package.split(":")
        if len(parts) != 2:
            return ("NON_DEPENDENCY_ISSUE", f"Invalid package format: {package}", _empty_extra)

        group_id, artifact_id = parts
        try:
            resp = self.session.get(
                MAVEN_CENTRAL_SEARCH,
                params={
                    "q": f'g:"{group_id}" AND a:"{artifact_id}"',
                    "rows": 5,
                    "wt": "json",
                    "core": "gav",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("response", {}).get("docs", [])
                if docs:
                    latest = docs[0].get("v", "")
                    if latest and _version_gte(latest, fix_version):
                        return (
                            "UNRESOLVED_DEPENDENCY",
                            f"{package} not pinned in {project_deps.project_name} "
                            f"{project_deps.version} — fix version {fix_version} "
                            f"exists on Maven Central ({latest}), but transitive "
                            f"version cannot be confirmed without full resolution",
                            _empty_extra,
                        )
        except requests.RequestException as e:
            logger.warning("Maven Central lookup failed for %s: %s", package, e)

        return (
            "UNRESOLVED_DEPENDENCY",
            f"{package} not directly managed in {project_deps.project_name} "
            f"{project_deps.version} (transitive dep, needs manual check)",
            _empty_extra,
        )

    # -- Caching helpers ------------------------------------------------------

    @staticmethod
    def _load_cache(
        path: Path, owner: str, repo: str, version: str
    ) -> ProjectDeps:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ProjectDeps(
            project_name=f"{owner}/{repo}",
            version=version,
            managed_versions=data.get("managed_versions", {}),
            direct_deps=data.get("direct_deps", {}),
            all_declared_deps=data.get("all_declared_deps", {}),
            properties=data.get("properties", {}),
            repo_url=data.get("repo_url", f"https://github.com/{owner}/{repo}"),
            release_tag=data.get("release_tag", ""),
            dep_sources=data.get("dep_sources", {}),
        )

    @staticmethod
    def _save_cache(path: Path, deps: ProjectDeps):
        data = {
            "managed_versions": deps.managed_versions,
            "direct_deps": deps.direct_deps,
            "all_declared_deps": deps.all_declared_deps,
            "properties": deps.properties,
            "repo_url": deps.repo_url,
            "release_tag": deps.release_tag,
            "dep_sources": deps.dep_sources,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# -- Version comparison -------------------------------------------------------


def _version_gte(version_a: str, version_b: str) -> bool:
    """Return True if version_a >= version_b (simplified Maven comparison)."""

    def _normalize(v: str) -> list[int]:
        v = re.sub(r"[.\-]?(RELEASE|Final|GA)$", "", v, flags=re.IGNORECASE)
        parts = re.split(r"[.\-]", v)
        nums: list[int] = []
        for p in parts:
            try:
                nums.append(int(p))
            except ValueError:
                break
        return nums

    a = _normalize(version_a)
    b = _normalize(version_b)
    max_len = max(len(a), len(b))
    a.extend([0] * (max_len - len(a)))
    b.extend([0] * (max_len - len(b)))
    return a >= b
