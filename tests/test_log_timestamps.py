"""Every service log line carries a timestamp (Ken, 2026-10-29: the log could not say when Duet read the vault)."""

import io
import logging
import logging.config
import re
import unittest

from armonica.logs import stamp_root, uvicorn_log_config

STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4} ")


class LogTimestamps(unittest.TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self.saved = (self.root.handlers[:], self.root.level)

    def tearDown(self):
        self.root.handlers[:], level = self.saved[0], self.saved[1]
        self.root.setLevel(level)

    def test_app_lines_through_root_are_stamped(self):
        buf = io.StringIO()
        self.root.handlers[:] = [logging.StreamHandler(buf)]
        self.root.setLevel(logging.INFO)
        stamp_root()
        logging.getLogger("armonica").info("IP allowlist pass: derived=%s", "160.79.104.1")
        line = buf.getvalue().splitlines()[-1]
        self.assertRegex(line, STAMP)
        self.assertTrue(line.endswith("IP allowlist pass: derived=160.79.104.1"))

    def test_uvicorn_access_and_default_formats_are_stamped(self):
        cfg = uvicorn_log_config()
        for name, formatter in cfg["formatters"].items():
            self.assertTrue(formatter["fmt"].startswith("%(asctime)s "), name)
        buf = io.StringIO()
        logging.config.dictConfig(cfg)
        access = logging.getLogger("uvicorn.access")
        access.handlers[0].stream = buf
        access.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5000", "POST", "/mcp", "1.1", 200)
        self.assertRegex(buf.getvalue().splitlines()[-1], STAMP)

    def test_default_uvicorn_config_is_not_mutated(self):
        from uvicorn.config import LOGGING_CONFIG

        uvicorn_log_config()
        self.assertFalse(LOGGING_CONFIG["formatters"]["access"]["fmt"].startswith("%(asctime)s"))


if __name__ == "__main__":
    unittest.main()
