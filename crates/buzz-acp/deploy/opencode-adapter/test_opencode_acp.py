"""WO #598: opencode adapter timeout must match MAX_TURN_DURATION and keep output.

Run from this directory:
  python3 -m unittest test_opencode_acp.py -v
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import opencode_acp as acp  # noqa: E402


class ResolveTimeoutSecs(unittest.TestCase):
    def test_explicit_opencode_timeout_wins(self):
        env = {
            "OPENCODE_TIMEOUT_SECS": "2400",
            "BUZZ_ACP_MAX_TURN_DURATION": "1500",
        }
        self.assertEqual(acp.resolve_timeout_secs(env), 2400)

    def test_falls_back_to_seat_max_turn_duration(self):
        env = {"BUZZ_ACP_MAX_TURN_DURATION": "2400"}
        self.assertEqual(acp.resolve_timeout_secs(env), 2400)

    def test_empty_explicit_falls_through_to_max_turn(self):
        env = {
            "OPENCODE_TIMEOUT_SECS": "  ",
            "BUZZ_ACP_MAX_TURN_DURATION": "2400",
        }
        self.assertEqual(acp.resolve_timeout_secs(env), 2400)

    def test_default_is_1500_when_neither_is_set(self):
        self.assertEqual(acp.resolve_timeout_secs({}), 1500)


class OxEnvAlignment(unittest.TestCase):
    def test_ox_env_append_sets_timeout_equal_to_max_turn(self):
        text = (HERE / "ox.env.append").read_text(encoding="utf-8")
        vals = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip()
        self.assertEqual(vals.get("OPENCODE_TIMEOUT_SECS"), "2400")
        self.assertEqual(vals.get("BUZZ_ACP_MAX_TURN_DURATION"), "2400")
        self.assertEqual(
            acp.resolve_timeout_secs(vals),
            int(vals["BUZZ_ACP_MAX_TURN_DURATION"]),
        )


class TimeoutOutput(unittest.TestCase):
    def test_format_keeps_partial_and_labels_killed_timeout(self):
        out = acp.format_killed_timeout("work product\nPR opened", 1500)
        self.assertIn("work product", out)
        self.assertIn("PR opened", out)
        self.assertIn("killed_timeout", out)
        self.assertIn("1500", out)

    def test_format_without_partial_still_labels_killed_timeout(self):
        out = acp.format_killed_timeout("", 1500)
        self.assertIn("killed_timeout", out)
        self.assertNotIn("timed out", out.lower().replace("killed_timeout", ""))

    def test_finish_after_timeout_preserves_partial_stdout(self):
        script = (
            "import sys, time\n"
            "print('PARTIAL-WORK', flush=True)\n"
            "time.sleep(30)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        t0 = time.monotonic()
        try:
            proc.communicate(timeout=0.5)
            self.fail("child should have exceeded the 0.5s cap")
        except subprocess.TimeoutExpired as exc:
            out = acp.finish_after_timeout(proc, 0.5, exc)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 8.0, "kill+drain must not wait out the child sleep")
        self.assertIn("PARTIAL-WORK", out)
        self.assertIn("killed_timeout", out)
        self.assertIsNotNone(proc.poll())


class TimeoutRpc(unittest.TestCase):
    def test_timeout_rpc_error_message_is_killed_timeout(self):
        msg = acp.timeout_rpc_error_message(1500)
        self.assertIn("killed_timeout", msg)
        self.assertTrue(msg.startswith("opencode:"))


if __name__ == "__main__":
    unittest.main()
