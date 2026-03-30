"""Azure DevOps client using 'az devops' CLI for auth + REST API fallback."""

import base64
import json
import logging
import subprocess
import tempfile
import time

import requests

logger = logging.getLogger(__name__)

ADO_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"


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
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"az CLI failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return json.loads(result.stdout)

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

        For az CLI: splits into two calls to avoid shell argument length limits
        when the discussion HTML is large (e.g., 30+ vulnerabilities).
        """
        if self._has_az_devops:
            # Step 1: Update state + assignment
            self._az_cli([
                "boards", "work-item", "update",
                "--id", str(work_item_id),
                "--state", state,
                "--fields", f"System.AssignedTo={assigned_to}",
            ])
            # Step 2: Add discussion via temp file to avoid arg length limits
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".html", delete=False, encoding="utf-8"
            ) as f:
                f.write(discussion)
                tmp_path = f.name
            try:
                return self._az_cli([
                    "boards", "work-item", "update",
                    "--id", str(work_item_id),
                    "--discussion", f"@{tmp_path}",
                ])
            except RuntimeError:
                # If @file syntax isn't supported, fall back to truncated inline
                logger.warning(
                    "Failed to add discussion via file for %d, trying inline (truncated)",
                    work_item_id,
                )
                # Truncate to ~4000 chars to stay within shell limits
                short = discussion[:4000] + "\n<p><em>(truncated — full detail in analysis-report.md)</em></p>"
                return self._az_cli([
                    "boards", "work-item", "update",
                    "--id", str(work_item_id),
                    "--discussion", short,
                ])
        body = [
            {"op": "replace", "path": "/fields/System.State", "value": state},
            {"op": "replace", "path": "/fields/System.AssignedTo", "value": assigned_to},
        ]
        self._patch(f"/wit/workitems/{work_item_id}?api-version=7.1", body)
        return self._post(
            f"/wit/workitems/{work_item_id}/comments?api-version=7.1-preview.4",
            {"text": discussion},
        )

    def add_work_item_comment(self, work_item_id: int, comment: str) -> dict:
        """Add a discussion comment to a work item."""
        if self._has_az_devops:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".html", delete=False, encoding="utf-8"
            ) as f:
                f.write(comment)
                tmp_path = f.name
            try:
                return self._az_cli([
                    "boards", "work-item", "update",
                    "--id", str(work_item_id),
                    "--discussion", f"@{tmp_path}",
                ])
            except RuntimeError:
                short = comment[:4000] + "\n<p><em>(truncated)</em></p>"
                return self._az_cli([
                    "boards", "work-item", "update",
                    "--id", str(work_item_id),
                    "--discussion", short,
                ])
        return self._post(
            f"/wit/workitems/{work_item_id}/comments?api-version=7.1-preview.4",
            {"text": comment},
        )
