#!/usr/bin/env python3
"""Serve the web UI locally, using the same handler Vercel uses.

    python3 tools/serve-web.py [--port 8000] [--host 0.0.0.0]

Serving ``web/`` statically and routing ``/api/obfuscate`` into
``api/obfuscate.handler`` means the deployed path and the tested path are one
implementation.  A separate dev backend would let the two drift, and the drift
always shows up after deploying.
"""

from __future__ import annotations

import argparse
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")
sys.path.insert(0, os.path.join(ROOT, "api"))

from obfuscate import handler as api_handler  # noqa: E402


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB, **kwargs)

    def do_POST(self):
        if self.path.rstrip("/") != "/api/obfuscate":
            self.send_error(404, "no such endpoint")
            return
        # The WSGI adapter already knows how to read the body and serialise the
        # response; handing it a start_response callback keeps one code path.
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        body = b"".join(api_handler(self._wsgi_environ(), start_response))
        code = int(captured["status"].split()[0])
        self.send_response(code)
        for key, value in captured["headers"]:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _wsgi_environ(self):
        length = int(self.headers.get("Content-Length") or 0)
        return {
            "REQUEST_METHOD": "POST",
            "CONTENT_LENGTH": str(length),
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "wsgi.input": self.rfile,
        }

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"couxobf web UI on http://{args.host}:{args.port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
