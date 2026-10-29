"""Every request body is capped before buffering (2026-10-29 pre-publication).

/login is exempt from the IP allowlist, and starlette's form parser would
otherwise buffer up to ~1GB per request (1000 fields x 1MB), so an
unauthenticated POST could exhaust server memory. A 40MB post to a live demo
drove RSS from 68MB to 113MB before this cap. BodyLimitMiddleware refuses an
oversized body with 413, by declared Content-Length and by streamed bytes, and
lets normal bodies through.
"""

import asyncio
import unittest

from armonica.server import BodyLimitMiddleware, MAX_REQUEST_BODY


async def echo_length(scope, receive, send):
    """A downstream app that drains the body, so a pass-through test reads it all."""
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(len(body)).encode()})


def drive(path, body, headers, cap=256):
    app = BodyLimitMiddleware(echo_length, max_body=cap)
    scope = {"type": "http", "method": "POST", "path": path, "headers": headers}
    chunks = [body[i:i + 64] for i in range(0, len(body), 64)] or [b""]
    queue = list(chunks)

    async def receive():
        if queue:
            chunk = queue.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(queue)}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, out


class BodyIsCapped(unittest.TestCase):
    def test_streamed_oversized_login_body_is_refused(self):
        status, _ = drive("/login", b"x" * 1024, headers=[])
        self.assertEqual(413, status)

    def test_declared_oversized_length_is_refused(self):
        status, _ = drive("/login", b"x" * 16,
                           headers=[(b"content-length", b"1048577")])
        self.assertEqual(413, status)

    def test_non_integer_length_is_refused(self):
        status, _ = drive("/login", b"x" * 16,
                           headers=[(b"content-length", b"not-a-number")])
        self.assertEqual(413, status)

    def test_small_body_passes_through(self):
        status, out = drive("/login", b"passphrase=hunter2", headers=[])
        self.assertEqual(200, status)
        self.assertEqual(b"18", out)

    def test_bodyless_request_passes_through(self):
        status, out = drive("/mcp", b"", headers=[])
        self.assertEqual(200, status)
        self.assertEqual(b"0", out)

    def test_default_cap_is_one_megabyte(self):
        self.assertEqual(1024 * 1024, MAX_REQUEST_BODY)

    def test_receive_after_body_delegates_so_disconnect_watcher_does_not_spin(self):
        # The MCP transport keeps a long-lived connection and polls receive()
        # waiting for http.disconnect. If the cap's replay kept returning
        # http.request forever, that poll busy-spins the event loop (it wedged
        # the live server once). After the buffered body, receive() must
        # delegate to the real receive and surface http.disconnect.
        seen = {"type": None, "reads": 0}

        async def watcher_app(scope, receive, send):
            await receive()                      # the request body
            msg = await receive()                # the disconnect poll
            seen["type"] = msg["type"]
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        app = BodyLimitMiddleware(watcher_app, max_body=1024)
        scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
        sequence = [{"type": "http.request", "body": b"hello", "more_body": False},
                    {"type": "http.disconnect"}]

        async def receive():
            seen["reads"] += 1
            return sequence[min(seen["reads"] - 1, len(sequence) - 1)]

        sent = []

        async def send(message):
            sent.append(message)

        asyncio.run(app(scope, receive, send))
        self.assertEqual("http.disconnect", seen["type"])


if __name__ == "__main__":
    unittest.main()
