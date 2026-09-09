"""Serve browser regressions without model calls: python tests/browser_server.py.

Open http://127.0.0.1:17832 and inspect window.browserRegression for results.
The tests use the actual frontend DOM and modules, with controlled event/API data.
"""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "web"), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
            content = html.replace("</body>", '<script type="module" src="/__tests__/refine.js"></script></body>')
            self._send(content, "text/html")
        elif path == "/__tests__/refine.js":
            self._send((ROOT / "tests" / "browser" / "refine.js").read_text(encoding="utf-8"), "text/javascript")
        else:
            super().do_GET()

    def _send(self, text, content_type):
        data = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 17832), Handler).serve_forever()
