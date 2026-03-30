"""Azure DevOps client using 'az devops' CLI for auth + REST API fallback."""

import base64
import json
import logging
import subprocess
import time

import requests

logger = logging.getLogger(__name__)

ADO_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"


def _sanitize_for_cli(text: str) -> str:
    """Replace non-ASCII characters with HTML entities or ASCII equivalents.

    The Windows az CLI uses cp1252 encoding internally which can't handle
    Unicode characters like em dashes, arrows, or emoji. Convert them to
    HTML entities so ADO renders them correctly.
    """
    replacements = {
        "\u2014": "&mdash;",     # —
        "\u2013": "&ndash;",     # –
        "\u2192": "&rarr;",      # →
        "\u2190": "&larr;",      # ←
        "\u2265": "&ge;",        # ≥
        "\u2264": "&le;",        # ≤
        "\u221e": "&infin;",     # ∞
        "\u2713": "&#10003;",    # ✓
        "\u2717": "&#10007;",    # ✗
        "\u2705": "&#9989;",     # ✅
        "\U0001f6e1": "&#128737;",  # 🛡️
        "\U0001f512": "&#128274;",  # 🔒
        "\U0001f916": "&#129302;",  # 🤖
    }
    for char, entity in replacements.items():
        text = text.replace(char, entity)
    # Catch any remaining non-ASCII characters
    safe = []
    for ch in text:
        if ord(ch) > 127:
            safe.append(f"&#{ord(ch)};")
        else:
            safe.append(ch)
    return "".join(safe)


class AdoClient:
    def __init__(self, org: str, project: str, pat: str | None = None):
        self.org = org
        self.project = project
        self.org_url = f"https://dev.azure.com/{org}"
        self.base_url = f"{self.org_url}/{project}/_apis"
        self._token = None
        self._token_type = None
        self._pat = pat
        self._has_az_devops = self._check_az_devops_cli()
        self._init_auth()

    # -- Authentication -------------------------------------------------------

    def _check_az_devops_cli(self) -> bool:
        """Check if the az devops extension is available and configured."""
        try:
            result = subprocess.run(
                ["az", "devops", "project", "show",
                 "--project", self.project,
                 "--org", self.org_url,
                 "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                logger.info("Azure DevOps CLI extension available and working")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def _init_auth(self):
        if self._has_az_devops:
            logger.info("Using Azure DevOps CLI (Entra ID via az login)")
            self._token_type = "az_cli"
            return
        if self._try_rest_token():
            logger.info("Authenticated via Azure CLI REST token")
            return
        if self._pat:
            self._token = self._pat
            self._token_type = "pat"
            logger.info("Authenticated via Personal Access Token")
            return
        raise RuntimeError(
            "No authentication available. Run 'az login' and install the "
            "az devops extension ('az extension add --name azure-devops'), "
            "or set ADO_PAT in .env"
        )

    def _try_rest_token(self) -> bool:
        try:
            result = subprocess.run(
                ["az", "account", "get-access-token",
                 "--resource", ADO_RESOURCE_ID,
                 "--output", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                self._token = data["accessToken"]
                self._token_type = "bearer"
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return False

    def _headers(self, content_type: str = "application/json") -> dict:
        if self._token_type == "bearer":
            auth = f"Bearer {self._token}"
        elif self._token_type == "pat":
            encoded = base64.b64encode(f":{self._token}".encode()).decode()
            auth = f"Basic {encoded}"
        else:
            return {"Content-Type": content_type}
        return {"Authorization": auth, "Content-Type": content_type}

    # -- az devops CLI helpers ------------------------------------------------

    def _az_cli(self, args: list[str], timeout: int = 60) -> dict | list:
        """Run an az devops/boards CLI command and return parsed JSON."""
        cmd = ["az"] + args + ["--org", self.org_url, "--output", "json"]
        logger.debug("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
        )
        # Decode output, trying utf-8 first then cp1252 (Windows az CLI)
        try:
            stdout = result.stdout.decode("utf-8")
        except UnicodeDecodeError:
            stdout = result.stdout.decode("cp1252", errors="replace")
        try:
            stderr = result.stderr.decode("utf-8")
        except UnicodeDecodeError:
            stderr = result.stderr.decode("cp1252", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(
                f"az CLI failed (exit {result.returncode}): {stderr.strip()}"
            )
        return json.loads(stdout)

    # -- Low-level HTTP (used when az CLI isn't available) --------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.get(url, headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, body: list) -> dict:
        url = f"{self.base_url}{path}"
        headers = self._headers(content_type="application/json-patch+json")
        resp = requests.patch(url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.post(url, headers=self._headers(), json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # -- Work Item Operations -------------------------------------------------

    def run_query(self, query_id: str) -> list[int]:
        """Run a saved ADO query and return work item IDs."""
        if self._has_az_devops:
            data = self._az_cli([
                "boards", "query",
                "--id", query_id,
                "--project", self.project,
            ])
            return [wi["id"] for wi in data]
        data = self._get(f"/wit/wiql/{query_id}", params={"api-version": "7.1"})
        return [wi["id"] for wi in data.get("workItems", [])]

    def get_work_item(self, work_item_id: int) -> dict:
        """Fetch a single work item with all fields."""
        if self._has_az_devops:
            return self._az_cli([
                "boards", "work-item", "show",
                "--id", str(work_item_id),
                "--expand", "all",
            ])
        data = self._get(
            f"/wit/workitems/{work_item_id}",
            params={"$expand": "all", "api-version": "7.1"},
        )
        return data

    def get_work_items(self, ids: list[int], batch_size: int = 200) -> list[dict]:
        """Fetch full work item details in batches."""
        if self._has_az_devops:
            # az boards doesn't have a batch fetch, use individual calls
            items: list[dict] = []
            for i, wi_id in enumerate(ids):
                try:
                    item = self.get_work_item(wi_id)
                    items.append(item)
                except Exception as e:
                    logger.warning("Failed to fetch work item %d: %s", wi_id, e)
                if (i + 1) % 25 == 0:
                    logger.info("Fetched %d / %d work items...", i + 1, len(ids))
                    time.sleep(0.3)
            return items

        # REST API batch fetch
        all_items: list[dict] = []
        for i in range(0, len(ids), batch_size):
            batch = ids[i : i + batch_size]
            id_str = ",".join(str(x) for x in batch)
            data = self._get(
                "/wit/workitems",
                params={"ids": id_str, "$expand": "all", "api-version": "7.1"},
            )
            all_items.extend(data.get("value", []))
            if i + batch_size < len(ids):
                time.sleep(0.5)
        return all_items

    def update_work_item_state(self, work_item_id: int, state: str) -> dict:
        """Change a work item's state."""
        if self._has_az_devops:
            return self._az_cli([
                "boards", "work-item", "update",
                "--id", str(work_item_id),
                "--state", state,
            ])
        body = [
            {"op": "replace", "path": "/fields/System.State", "value": state}
        ]
        return self._patch(
            f"/wit/workitems/{work_item_id}?api-version=7.1", body
        )

    def update_work_item(
        self, work_item_id: int, state: str, assigned_to: str,
        discussion: str,
    ) -> dict:
        """Update a work item's state, assignment, and add a discussion comment.

        Uses az CLI for state/assignment, and az rest for the discussion comment
        to avoid shell argument length limits with large HTML.
        """
        if self._has_az_devops:
            # Extract email from "Name <email>" format for az CLI compatibility
            assign_value = assigned_to
            if "<" in assigned_to and ">" in assigned_to:
                assign_value = assigned_to.split("<")[1].rstrip(">").strip()
            # Step 1: Update state + assignment via az boards
            self._az_cli([
                "boards", "work-item", "update",
                "--id", str(work_item_id),
                "--state", state,
                "--fields", f"System.AssignedTo={assign_value}",
            ])
            # Step 2: Add discussion via az rest (no arg length limit)
            return self._add_comment_via_rest(work_item_id, discussion)
        body = [
            {"op": "replace", "path": "/fields/System.State", "value": state},
            {"op": "replace", "path": "/fields/System.AssignedTo", "value": assigned_to},
        ]
        self._patch(f"/wit/workitems/{work_item_id}?api-version=7.1", body)
        return self._post(
            f"/wit/workitems/{work_item_id}/comments?api-version=7.1-preview.4",
            {"text": discussion},
        )

    def _add_comment_via_rest(self, work_item_id: int, comment: str) -> dict:
        """Add a discussion comment using direct REST API with az login token.
        Falls back to az boards --discussion with ASCII-safe HTML if REST fails.
        """
        url = (
            f"{self.org_url}/{self.project}/_apis/wit/workitems/"
            f"{work_item_id}/comments?api-version=7.1-preview.4"
        )
        # Try REST API with bearer token first
        try:
            result = subprocess.run(
                [
                    "az", "account", "get-access-token",
                    "--resource", ADO_RESOURCE_ID,
                    "--query", "accessToken",
                    "--output", "tsv",
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                token = result.stdout.strip()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                resp = requests.post(
                    url,
                    headers=headers,
                    json={"text": comment},
                    timeout=30,
                )
                if resp.status_code in (200, 201):
                    return resp.json()
                logger.debug(
                    "REST comment failed for %d (HTTP %d), using az boards fallback",
                    work_item_id, resp.status_code,
                )
        except Exception as e:
            logger.debug("REST token error for %d: %s", work_item_id, e)

        # Fallback: az boards --discussion with ASCII-safe HTML
        safe_comment = _sanitize_for_cli(comment)
        return self._az_cli([
            "boards", "work-item", "update",
            "--id", str(work_item_id),
            "--discussion", safe_comment,
        ])

    def add_work_item_comment(self, work_item_id: int, comment: str) -> dict:
        """Add a discussion comment to a work item."""
        if self._has_az_devops:
            return self._add_comment_via_rest(work_item_id, comment)
        return self._post(
            f"/wit/workitems/{work_item_id}/comments?api-version=7.1-preview.4",
            {"text": comment},
        )
