import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("updater", Path(__file__).with_name("update_blocklist.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class UpdateBlocklistTests(unittest.TestCase):
    def setUp(self):
        self.sources = (("one", "https://example.test/one", 1, 2000),
                        ("two", "https://example.test/two", 1, 2000))
        self.source_data = {
            "one": b"Mailinator.com\nshared.example\n" + b"#" * 10000,
            "two": b"mailinator.com\nother.example\n" + b"#" * 10000,
        }
        self.protected = ("\n".join(updater.REQUIRED_PROTECTED) + "\n").encode()
        self.patcher = patch.object(updater, "SOURCES", self.sources)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def build(self, own=b"local.example\n", protected=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return updater.build(self.source_data, b"mailinator.com\n", own,
                                 self.protected if protected is None else protected)

    def test_merge_normalizes_sorts_and_retains_local_inclusions(self):
        self.assertEqual(self.build(), b"local.example\nmailinator.com\nother.example\nshared.example\n")

    def test_rejects_protected_and_malformed_domains(self):
        for domain in sorted(updater.REQUIRED_PROTECTED):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                self.build(own=(domain + "\n").encode())
        with self.assertRaises(ValueError):
            self.build(own=b"not a domain\n")

    def test_rejects_missing_required_protection(self):
        with self.assertRaises(ValueError):
            self.build(protected=b"gmail.com\n")

    def test_exclusions_persist_and_do_not_weaken_protected_checks(self):
        result = updater.build(self.source_data, b"mailinator.com\n", b"local.example\n",
                               self.protected, b"other.example\n")
        self.assertNotIn(b"other.example\n", result)
        with self.assertRaisesRegex(ValueError, "conflict"):
            updater.build(self.source_data, b"mailinator.com\n", b"other.example\n",
                          self.protected, b"other.example\n")
        self.source_data["one"] += b"\ngmail.com\n"
        with self.assertRaisesRegex(ValueError, "Protected legitimate"):
            updater.build(self.source_data, b"mailinator.com\n", b"local.example\n",
                          self.protected, b"gmail.com\n")

    def test_reviewed_exclusions_are_absent(self):
        excluded = updater.parse((updater.ROOT / "assets/blocklist-exclusions.txt").read_bytes(), "excluded")
        current = updater.parse((updater.ROOT / "assets/blocklist.txt").read_bytes(), "current")
        self.assertFalse(excluded & current)

    def test_rejects_source_failure(self):
        payload = self.source_data["one"]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/one":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_error(503)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port
        sources = (("one", f"http://127.0.0.1:{port}/one", 1, 2000),
                   ("two", f"http://127.0.0.1:{port}/two", 1, 2000))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            assets.mkdir()
            target = assets / "blocklist.txt"
            target.write_bytes(b"mailinator.com\n")
            with patch.object(updater, "ROOT", root), patch.object(updater, "SOURCES", sources), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError) as failure:
                    updater.main()
                failure.exception.close()
            self.assertEqual(target.read_bytes(), b"mailinator.com\n")

    def test_rejects_abnormal_delta(self):
        self.source_data["one"] = b"mailinator.com\n" + b"".join(
            f"example{i}.com\n".encode() for i in range(1100))
        with self.assertRaisesRegex(ValueError, "Abnormal"):
            self.build()

    def test_rejects_bad_source_size_count_and_missing_known_domain(self):
        cases = (
            (b"mailinator.com\n", "size outside limits"),
            (b"#" * 10000, "count outside limits"),
            (b"unrelated.example\n" + b"#" * 10000, "lacks known domains"),
        )
        for payload, error in cases:
            with self.subTest(error=error):
                self.source_data["one"] = payload
                with self.assertRaisesRegex(ValueError, error):
                    self.build()

    def test_successful_update_writes_sorted_candidate_to_test_directory(self):
        data = self.source_data

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                key = self.path.removeprefix("/")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data[key])

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port
        sources = (("one", f"http://127.0.0.1:{port}/one", 1, 2000),
                   ("two", f"http://127.0.0.1:{port}/two", 1, 2000))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            assets.mkdir()
            target = assets / "blocklist.txt"
            target.write_bytes(b"mailinator.com\n")
            (assets / "confirmed-disposable-domains.txt").write_bytes(b"local.example\n")
            (assets / "blocklist-exclusions.txt").write_bytes(b"other.example\n")
            (assets / "legitimate-domains.txt").write_bytes(self.protected)
            with patch.object(updater, "ROOT", root), patch.object(updater, "SOURCES", sources), \
                 contextlib.redirect_stdout(io.StringIO()):
                updater.main()
            self.assertEqual(target.read_bytes(), b"local.example\nmailinator.com\nshared.example\n")

    def test_confirmed_domains_are_in_local_list(self):
        own = updater.parse((updater.ROOT / "assets/confirmed-disposable-domains.txt").read_bytes(), "own")
        self.assertEqual(own, {"emailnox.live", "emailinbo.live", "olipii.com", "ruutukf.com",
                               "gmeenramy.com", "tanpony.com", "lnovic.com", "ooynib.com",
                               "bwmyga.com", "fldubai.com"})
        self.assertTrue(own <= set(self.build(own=("\n".join(own) + "\n").encode()).decode().splitlines()))
        current = updater.parse((updater.ROOT / "assets/blocklist.txt").read_bytes(), "current")
        self.assertTrue(own <= current)

    def test_workflow_requires_all_checks_before_running_merge_script(self):
        workflow = (updater.ROOT / ".github/workflows/update-blocklist.yml").read_text()
        merge_step = workflow.split("- name: Merge reviewed blocklist update", 1)[1]
        for gate in (
            "steps.candidate_tests.outcome == 'success'",
            "steps.pr_head.outcome == 'success'",
            "steps.pr_checks.outcome == 'success'",
            "steps.cururu_review.outcome == 'success'",
            "steps.cururu_review.outputs.review_status == 'completed'",
            "steps.cururu_review.outputs.quality_gate_passed == 'true'",
            "steps.cururu_review.outputs.analysis_status == 'passed'",
        ):
            self.assertIn(gate, merge_step)
        self.assertNotIn("BLOCKLIST_NATIVE_AUTO_MERGE", workflow)

    def test_merge_is_limited_to_expected_app_scope_head_and_base(self):
        import os
        import subprocess

        script = updater.ROOT / ".github/scripts/merge-reviewed-blocklist.sh"
        with tempfile.TemporaryDirectory() as directory:
            fake_gh = Path(directory) / "gh"
            fake_gh.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
endpoint = next(arg for arg in sys.argv[2:] if arg.startswith("repos/"))
if endpoint.endswith("/pulls/42"):
    repo = {"full_name": "test/repo"}
    print(json.dumps({"state": "open", "draft": False,
        "user": {"login": os.environ.get("ACTUAL_AUTHOR", "test-app[bot]")},
        "head": {"repo": repo, "ref": "automation/update-blocklist",
                 "sha": os.environ.get("ACTUAL_HEAD", "reviewed")},
        "base": {"repo": repo, "ref": "main", "sha": "trusted-base"}}))
elif endpoint.endswith("/files"):
    print(os.environ.get("ACTUAL_FILES", "assets/blocklist.txt"))
elif "/contents/" in endpoint:
    print(os.environ.get("ACTUAL_BLOB", "candidate"))
elif "/commits/" in endpoint:
    print(os.environ.get("PARENTS", "trusted-base"))
elif endpoint.endswith("/branches/main"):
    print(os.environ.get("ACTUAL_BASE", "trusted-base"))
elif endpoint.endswith("/pulls/42/merge"):
    assert "PUT" in sys.argv and "sha=reviewed" in sys.argv and "merge_method=merge" in sys.argv
    Path(os.environ["MUTATION_LOG"]).touch()
    print(os.environ.get("MERGE_RESPONSE", '{"merged":true,"sha":"merge-commit"}'))
else:
    sys.exit(f"Unexpected endpoint: {endpoint}")
""")
            fake_gh.chmod(0o755)
            marker = Path(directory) / "merge-request"
            env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                       GITHUB_REPOSITORY="test/repo", APP_SLUG="test-app", PR_NUMBER="42",
                       GITHUB_SHA="trusted-base", HEAD_SHA="reviewed", CANDIDATE_BLOB="candidate",
                       MUTATION_LOG=str(marker))
            for overrides, should_request, should_succeed in (
                ({"ACTUAL_AUTHOR": "other-user"}, False, False),
                ({"ACTUAL_HEAD": "unreviewed"}, False, False),
                ({"ACTUAL_FILES": "assets/blocklist.txt\n.github/workflows/ci.yml"}, False, False),
                ({"ACTUAL_BLOB": "different"}, False, False),
                ({"PARENTS": "trusted-base\nextra-parent"}, False, False),
                ({"ACTUAL_BASE": "new-base"}, False, False),
                ({"MERGE_RESPONSE": '{"merged":false}'}, True, False),
                ({}, True, True),
            ):
                with self.subTest(overrides=overrides):
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", str(script)], check=False, capture_output=True, text=True,
                        env=dict(env, **overrides),
                    )
                    self.assertEqual(marker.exists(), should_request, result.stderr)
                    self.assertEqual(result.returncode == 0, should_succeed, result.stderr)

    def test_review_and_safety_use_separate_concurrency_groups(self):
        workflow = (updater.ROOT / ".github/workflows/cururu-review.yml").read_text()
        self.assertIn("group: cururu-review-${{", workflow)
        self.assertIn("group: cururu-safety-${{", workflow)
        self.assertNotIn("group: cururu-${{ github.event_name }}-", workflow)


if __name__ == "__main__":
    unittest.main()
