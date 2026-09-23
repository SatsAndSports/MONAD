"""Small harness regressions; run in the documented Nutshell environment."""

import os
import signal
import subprocess
import sys
import time
import unittest

import run


class HarnessTests(unittest.TestCase):
    def test_loopback_origins(self):
        for url in ("http://127.0.0.1:1234", "http://[::1]:1234"):
            run.loopback_url(url)
        for url in (
            "http://127.0.0.1:1234@evil.example",
            "http://user@127.0.0.1:1234",
            "http://@127.0.0.1:1234",
            " http://127.0.0.1",
            "http:127.0.0.1",
            "https://127.0.0.1",
            "http://localhost",
            "http://192.0.2.1",
            "http://[::2]",
            "http://127.0.0.1/path",
            "http://127.0.0.1?",
            "http://127.0.0.1#x",
            "http://127.0.0.1:bad",
        ):
            with self.subTest(url=url), self.assertRaises((AssertionError, ValueError)):
                run.loopback_url(url)

    def test_redirects_disabled(self):
        self.assertIsNone(
            run.NoRedirect().redirect_request(
                None, None, 302, None, None, "http://example.com"
            )
        )

    def test_cleanup_after_leader_exit(self):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os, signal, time; pid=os.fork(); "
                "os._exit(0) if pid else None; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print(os.getpid(), flush=True); time.sleep(60)",
            ],
            start_new_session=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            descendant = int(child.stdout.readline())
            child.wait(timeout=5)
            run.stop(child)
            # A killed orphan can briefly remain a zombie until PID 1 reaps it.
            status = f"/proc/{descendant}/stat"
            deadline = time.monotonic() + 5
            while os.path.exists(status):
                with open(status) as stream:
                    if stream.read().split()[2] == "Z":
                        break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
        finally:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.stdout.close()


if __name__ == "__main__":
    unittest.main()
