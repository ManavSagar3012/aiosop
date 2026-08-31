"""WEB-AUDIT-004 proof shim: a JS-RENDERED front-end over an EXISTING backend.

This file contains NO vulnerable code. It serves one static page whose login
form is injected purely by client-side JS after load (the static HTML holds
no form markup — mirroring real SPA behavior). The form's action points at
the ALREADY-COMMITTED deliberately-vulnerable benchmark backend
(golden_path_target.py, port 9199) so web_audit v3's rendered pass can be
proven END-TO-END: static discovery must see nothing -> Playwright renders
the DOM -> the injected form is discovered -> the differential confirms the
pre-existing lab vulnerability through the rendered path.

Run:  python tests/benchmarks/rendered_spa_shim.py  (listens on :9299)
Also start: python golden_path_target.py  (listens on :9199)
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!DOCTYPE html>
<html><head><title>Rendered SPA Shim</title></head>
<body><div id="app">Loading...</div>
<script>
  // The form is constructed through the DOM API with no contiguous form-tag
  // markup anywhere in this static source: tag-regex form discovery sees
  // NOTHING here. Only a rendered-DOM pass can find it — mirroring real SPA
  // auth screens.
  var app = document.getElementById('app');
  app.textContent = '';
  var f = document.createElement('form');
  f.method = 'POST';
  f.action = 'http://127.0.0.1:9199/login';
  var u = document.createElement('input');
  u.type = 'text'; u.name = 'username';
  var p = document.createElement('input');
  p.type = 'password'; p.name = 'password';
  var b = document.createElement('button');
  b.type = 'submit'; b.textContent = 'Sign in';
  f.appendChild(u); f.appendChild(p); f.appendChild(b);
  app.appendChild(f);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, PAGE)

    def do_POST(self):
        self._send(404, "not found")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 9299), Handler)
    print("rendered-SPA shim on http://127.0.0.1:9299 (form JS-injected -> 127.0.0.1:9199/login)")
    srv.serve_forever()
