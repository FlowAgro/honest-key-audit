"""
HonestKeyAudit — interface web local (sem dependencias alem de cryptography)
============================================================================
Um servidor local simples: cole um certificado/chave (PEM) no navegador e
receba o relatorio de auditoria. Roda so' na sua maquina (localhost).

  python src/webapp.py            # abre http://localhost:8000
  python src/webapp.py 8080       # porta alternativa

Escopo defensivo: audite as SUAS chaves. Nada e' enviado para a internet —
tudo roda localmente.
"""
import os, sys, html
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyaudit

PAGE = """<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HonestKeyAudit</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:820px;
   margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:.2rem}} .sub{{color:#666;margin-top:0}}
 textarea{{width:100%;height:220px;font-family:ui-monospace,Menlo,Consolas,monospace;
   font-size:.85rem;padding:.7rem;border:1px solid #ccc;border-radius:8px;box-sizing:border-box}}
 button{{margin-top:.7rem;padding:.6rem 1.4rem;font-size:1rem;border:0;border-radius:8px;
   background:#1f6feb;color:#fff;cursor:pointer}}
 .card{{margin-top:1.3rem;padding:1rem 1.2rem;border-radius:10px;border:1px solid #e2e2e2;background:#fff}}
 .sum{{font-weight:600;font-size:1.05rem;margin-bottom:.5rem}}
 .f{{padding:.4rem .6rem;border-radius:6px;margin:.35rem 0;font-size:.92rem}}
 .VULN{{background:#fdecea;border-left:4px solid #d33}}
 .OK{{background:#eaf6ec;border-left:4px solid #2a2}}
 .INFO{{background:#eef2f7;border-left:4px solid #789}}
 .foot{{color:#888;font-size:.8rem;margin-top:2rem}}
 code{{background:#f0f0f0;padding:.1rem .3rem;border-radius:4px}}
</style></head><body>
<h1>HonestKeyAudit</h1>
<p class="sub">Auditor defensivo de chaves RSA &amp; ECC — cole um certificado ou chave pública (PEM) e receba o diagnóstico. Tudo roda localmente; nada é enviado para a internet.</p>
<form method="post" action="/audit">
<textarea name="key" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----&#10;&#10;(ou -----BEGIN PUBLIC KEY-----, ou uma chave OpenSSH ssh-rsa/ssh-ed25519...)">{input}</textarea>
<br><button type="submit">Auditar</button>
</form>
{report}
<p class="foot">HonestKeyAudit — base científica: <a href="https://doi.org/10.5281/zenodo.14553556">DOI 10.5281/zenodo.14553556</a>. Uso defensivo: audite as suas próprias chaves.</p>
</body></html>"""

def render_report(data):
    if not data.strip():
        return ""
    res = keyaudit.audit_bytes(data.encode("utf-8", "replace"))
    if res is None:
        return ('<div class="card"><div class="sum">Não reconheci esta entrada.</div>'
                '<div class="f INFO">Cole um certificado X.509, uma chave pública PEM/DER, '
                'ou uma chave OpenSSH válida.</div></div>')
    resumo, findings = res
    rows = "".join(f'<div class="f {lvl}">{html.escape(txt)}</div>' for lvl, txt in findings)
    vuln = any(l == "VULN" for l, _ in findings)
    head = ("⚠️ VULNERÁVEL — " if vuln else "✅ ") + html.escape(resumo)
    return f'<div class="card"><div class="sum">{head}</div>{rows}</div>'

class Handler(BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        self._send(PAGE.format(input="", report=""))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode("utf-8", "replace")
        key = parse_qs(raw).get("key", [""])[0]
        self._send(PAGE.format(input=html.escape(key), report=render_report(key)))

    def log_message(self, *a):  # silencioso
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"HonestKeyAudit rodando em http://localhost:{port}  (Ctrl+C para parar)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nencerrado.")

if __name__ == "__main__":
    main()
