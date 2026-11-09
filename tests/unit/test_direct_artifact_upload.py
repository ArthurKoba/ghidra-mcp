from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from bridge_mcp_ghidra.direct_upload import _safe_name, direct_artifact_upload


class DirectArtifactUploadTests(unittest.TestCase):
    def test_safe_name_normalizes_basename(self) -> None:
        self.assertEqual(_safe_name("firmware.bin"), "firmware.bin")
        self.assertEqual(_safe_name("../firmware.bin"), "firmware.bin")
        with self.assertRaises(ValueError):
            _safe_name("firmware image.bin")

    def test_raw_upload_writes_file_and_verifies_digest(self) -> None:
        payload = b"firmware" * 1024

        async def run_in_worker(func, project_id):
            return {"project_id": project_id}

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GHIDRA_MCP_FILE_ROOT": tmp},
            clear=False,
        ), patch(
            "bridge_mcp_ghidra.direct_upload.state.run_in_worker",
            new=AsyncMock(side_effect=run_in_worker),
        ):
            app = Starlette(
                routes=[Route("/internal/artifacts/upload", direct_artifact_upload, methods=["POST"])]
            )
            with TestClient(app) as client:
                response = client.post(
                    "/internal/artifacts/upload?project_id=project-1&name=firmware.bin",
                    content=payload,
                    headers={
                        "X-Koba-Proxy-Origin": "analysis",
                        "X-Artifact-Size": str(len(payload)),
                        "X-Artifact-SHA256": hashlib.sha256(payload).hexdigest(),
                    },
                )

            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertEqual(body["transfer_method"], "direct_raw")
            target = Path(body["path"])
            self.assertTrue(target.is_file())
            self.assertEqual(target.read_bytes(), payload)

    def test_raw_upload_requires_analysis_origin(self) -> None:
        app = Starlette(
            routes=[Route("/internal/artifacts/upload", direct_artifact_upload, methods=["POST"])]
        )
        with TestClient(app) as client:
            response = client.post(
                "/internal/artifacts/upload?project_id=project-1&name=firmware.bin",
                content=b"x",
            )
        self.assertEqual(response.status_code, 403)


    def test_direct_cleanup_is_idempotent_and_restricted_to_uploads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GHIDRA_MCP_FILE_ROOT": tmp}, clear=False
        ), patch(
            "bridge_mcp_ghidra.direct_upload.state.run_in_worker", new=AsyncMock()
        ):
            app = Starlette(routes=[Route(
                "/internal/artifacts/upload", direct_artifact_upload, methods=["POST", "DELETE"]
            )])
            with TestClient(app) as client:
                uploaded = client.post(
                    "/internal/artifacts/upload", params={"project_id": "p", "name": "test.bin"},
                    content=b"artifact", headers={"X-Koba-Proxy-Origin": "analysis"},
                ).json()
                target = Path(uploaded["path"])
                headers = {"X-Koba-Proxy-Origin": "analysis"}
                for deleted in [True, False]:
                    response = client.delete(
                        "/internal/artifacts/upload", params={"project_id": "p", "path": str(target)},
                        headers=headers,
                    )
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), {"success": True, "deleted": deleted})
                self.assertFalse(target.exists())
                untouched = Path(tmp) / "existing.bin"
                untouched.write_bytes(b"keep")
                rejected = client.delete(
                    "/internal/artifacts/upload", params={"project_id": "p", "path": str(untouched)},
                    headers=headers,
                )
                self.assertEqual(rejected.status_code, 400)
                self.assertEqual(untouched.read_bytes(), b"keep")
                denied = client.delete(
                    "/internal/artifacts/upload", params={"project_id": "p", "path": str(target)}
                )
                self.assertEqual(denied.status_code, 403)

    def test_direct_cleanup_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GHIDRA_MCP_FILE_ROOT": tmp}, clear=False
        ), patch(
            "bridge_mcp_ghidra.direct_upload.state.run_in_worker", new=AsyncMock()
        ):
            root = Path(tmp) / ".koba-direct"
            root.mkdir()
            outside = Path(tmp) / "keep.bin"
            outside.write_bytes(b"keep")
            link = root / (("a" * 32) + "-test.bin")
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("Host does not permit creating symlinks")
            app = Starlette(routes=[Route(
                "/internal/artifacts/upload", direct_artifact_upload, methods=["DELETE"]
            )])
            with TestClient(app) as client:
                response = client.delete(
                    "/internal/artifacts/upload", params={"project_id": "p", "path": str(link)},
                    headers={"X-Koba-Proxy-Origin": "analysis"},
                )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(outside.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
