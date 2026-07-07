"""
HonestKeyAudit — scanner de endpoints TLS AO VIVO (auditoria de chaves reais)
=============================================================================
Conecta a dominios HTTPS reais, pega o certificado, extrai a chave publica e
roda a auditoria completa (Fermat/mod-M/ROCA/Wiener por chave; batch-GCD e
anomalia estatistica na populacao). Aponte para os SEUS dominios.

Uso:
  python src/scan_live.py                 # lista embutida de dominios variados
  python src/scan_live.py a.com b.org ...  # seus dominios
  python src/scan_live.py --file doms.txt  # um dominio por linha

Escopo defensivo: certificados TLS sao PUBLICOS (o servidor os apresenta a
qualquer cliente). Auditar a propria chave publica de um servico e' legitimo.
"""
import os, sys, ssl, socket, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keyaudit
from gen_anomaly import audit_generator
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

DEFAULT_DOMAINS = [
    # grandes (referencia)
    "google.com","cloudflare.com","github.com","amazon.com","microsoft.com",
    "apple.com","wikipedia.org","mozilla.org","python.org","debian.org",
    "letsencrypt.org","stackoverflow.com","reddit.com","netflix.com","spotify.com",
    "paypal.com","stripe.com","dropbox.com","gitlab.com","bitbucket.org",
    "zenodo.org","arxiv.org","ieee.org","acm.org","springer.com",
    "gnu.org","kernel.org","openssl.org","nginx.org","apache.org",
    # governos (mundo todo — pilhas mais antigas/variadas)
    "gov.uk","usa.gov","europa.eu","gov.br","india.gov.in","gov.za","gov.au",
    "canada.ca","gov.sg","gov.pl","gouvernement.fr","bund.de","gov.it","gov.ie",
    # universidades (varias regioes)
    "usp.br","ufu.br","unicamp.br","mit.edu","stanford.edu","ox.ac.uk","cam.ac.uk",
    "u-tokyo.ac.jp","tsinghua.edu.cn","uct.ac.za","unam.mx","uba.ar","iitb.ac.in",
    # orgs menores / cauda mais longa
    "fsf.org","eff.org","torproject.org","freebsd.org","openbsd.org","gentoo.org",
    "archlinux.org","videolan.org","gimp.org","blender.org","postgresql.org",
    "sqlite.org","curl.se","wireshark.org","haproxy.org","proftpd.org",
    "openldap.org","isc.org","ntp.org","dovecot.org","postfix.org",
]

def fetch_cert(host, port=443, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--file")
    a = ap.parse_args()
    domains = list(a.domains)
    if a.file:
        domains += [l.strip() for l in open(a.file) if l.strip() and not l.startswith("#")]
    if not domains:
        domains = DEFAULT_DOMAINS

    print(f"=== HonestKeyAudit LIVE — {len(domains)} dominios ===\n")
    keys = []
    for host in domains:
        try:
            cert = fetch_cert(host)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                pn = pub.public_numbers()
                keys.append(dict(host=host, kind="rsa", n=pn.n, e=pn.e, pub=pub))
                info = f"RSA {pn.n.bit_length()}b e={pn.e}"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                keys.append(dict(host=host, kind="ec", pub=pub))
                info = f"EC {pub.curve.name}"
            else:
                info = "outro"
            resumo, findings = keyaudit.audit_single(pub)
            vuln = any(f[0] == "VULN" for f in findings)
            print(f"  {host:<22} {info:<22} {'*** VULNERAVEL ***' if vuln else 'ok'}")
            if vuln:
                for lvl, txt in findings:
                    if lvl == "VULN": print(f"        - {txt}")
        except Exception as ex:
            print(f"  {host:<22} (falhou: {type(ex).__name__})")

    # ---- analise da populacao ----
    rsa_keys = [k for k in keys if k["kind"] == "rsa"]
    ec_keys = [k for k in keys if k["kind"] == "ec"]
    print(f"\n--- coletado: {len(keys)} chaves ({len(rsa_keys)} RSA, {len(ec_keys)} EC) ---")

    if ec_keys:
        from collections import Counter
        curves = Counter(k["pub"].curve.name for k in ec_keys)
        print(f"  curvas EC: {dict(curves)}")
    if rsa_keys:
        from collections import Counter
        sizes = Counter(k["n"].bit_length() for k in rsa_keys)
        exps = Counter(k["e"] for k in rsa_keys)
        print(f"  tamanhos RSA: {dict(sizes)}")
        print(f"  expoentes RSA: {dict(exps)}  (65537 e' o esperado; outro valor e' incomum)")

        # FINGERPRINT DE GERADOR (nossa teoria em chaves reais):
        # f = N/2^(bits-2). Gerador padrao FIPS/OpenSSL forca 2 bits altos => f >= 2.25.
        # f < 2.25 = gerador NAO-padrao no mundo real (assinatura diferente = achado real).
        def _lead(N):
            b = N.bit_length(); shift = b - 2 - 52
            return (N >> shift)/float(2**52) if shift > 0 else N/float(2**(b-2))
        fvals = [_lead(k["n"]) for k in rsa_keys]
        nonstd = [(rsa_keys[i]["host"], f) for i, f in enumerate(fvals) if f < 2.25]
        print(f"  fingerprint (valor lider f=N/2^(bits-2)): min={min(fvals):.3f} max={max(fvals):.3f}")
        print(f"    f>=2.25 (padrao FIPS/OpenSSL, 2 bits altos): {sum(1 for f in fvals if f>=2.25)}/{len(fvals)}")
        if nonstd:
            print(f"    *** {len(nonstd)} chave(s) com f<2.25 = GERADOR NAO-PADRAO (assinatura real diferente):")
            for host, f in nonstd:
                print(f"        {host}: f={f:.3f}")
        else:
            print(f"    (nenhuma abaixo de 2.25 — todas as chaves RSA reais seguem o padrao dos 2 bits altos)")

        Ns = [k["n"] for k in rsa_keys]
        if len(Ns) >= 2:
            from rsa_audit import det_batch_gcd
            bg = det_batch_gcd(Ns)
            shared = [rsa_keys[i]["host"] for i, b in enumerate(bg) if b[0]]
            print(f"\n  [BATCH-GCD entre sites] " + (
                f"!!! FATOR COMPARTILHADO em {shared} — achado REAL !!!" if shared
                else "nenhum fator compartilhado (esperado em sites bem geridos)."))
        # NOTA HONESTA: NAO rodar o teste de anomalia ABSOLUTO numa populacao de
        # geradores MISTURADOS (varios CAs/libs). Ele so' faz sentido dentro da saida
        # de UM gerador (via baseline/drift, drift_monitor.py). Contra o uniforme puro,
        # chaves OpenSSL legitimas ja' desviam (restricao dos 2 bits) -> falso-positivo.
        print(f"  [nota] anomalia de populacao NAO se aplica a fontes misturadas — "
              f"use drift_monitor.py com baseline de UM gerador confiavel.")

if __name__ == "__main__":
    main()
