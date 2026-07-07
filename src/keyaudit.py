"""
HonestKeyAudit — auditor unificado que lê CHAVES REAIS (o "app")
================================================================
Aponta para certificados/chaves de verdade (PEM/DER X.509, chaves publicas
RSA/EC, chaves SSH) e produz um relatorio.

Detectores de CHAVE PUBLICA RSA (so' precisa de N,e):
  - Fermat (|p-q| pequeno)                     [rsa_audit]
  - mod-M estilo ROCA (heuristico rapido)      [rsa_audit]
  - ROCA real, CVE-2017-15361 (Infineon)       [roca]
  - WIENER (expoente privado d pequeno)        [aqui]
Cross-chave (corpus/diretorio):
  - Batch-GCD (fator compartilhado por PRNG ruim)  [rsa_audit]
 EC:
  - curva padrao + ponto valido (o parser 'cryptography' valida on-curve);
    o risco alto de ECC (reuso de nonce) e' auditado em ecc_audit.py ('sigs').

Uso (CLI):
  python src/keyaudit.py <arquivo-ou-pasta> [<mais-arquivos> ...]
Interface web:
  python src/webapp.py     (abre http://localhost:8000)

Escopo defensivo: rode nas SUAS chaves, sinteticas, ou datasets publicos com
divulgacao responsavel.
"""
import os, sys, glob
from math import isqrt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_audit import det_fermat, det_modM, det_batch_gcd
from roca import det_roca
import ecc_audit  # noqa (registro/curvas; usado indiretamente)

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_der_public_key, load_ssh_public_key)
from cryptography.hazmat.primitives.asymmetric import rsa, ec

_CURVE_MAP = {"secp256r1": "P-256", "prime256v1": "P-256", "secp256k1": "secp256k1"}
_STD_CURVES = {"secp256r1", "prime256v1", "secp384r1", "secp521r1", "secp256k1"}

# ---------------- detector: ataque de Wiener (d pequeno) ----------------
def det_wiener(e, N):
    a, b = e, N
    num0, num1 = 0, 1
    den0, den1 = 1, 0
    while b:
        qq = a // b
        a, b = b, a - qq*b
        num0, num1 = num1, qq*num1 + num0
        den0, den1 = den1, qq*den1 + den0
        k, d = num1, den1
        if k == 0:
            continue
        if (e*d - 1) % k != 0:
            continue
        phi = (e*d - 1) // k
        s = N - phi + 1
        disc = s*s - 4*N
        if disc < 0:
            continue
        t = isqrt(disc)
        if t*t != disc or (s + t) % 2 != 0:
            continue
        p, q = (s + t)//2, (s - t)//2
        if p*q == N:
            return (True, f"WIENER: expoente privado d pequeno (d={d}) => chave QUEBRADA. p={p}")
    return (False, "resistente a Wiener (d nao e' pequeno).")

# ---------------- carregar chaves reais ----------------
def _load_pubkey_from_bytes(data):
    for loader in (
        lambda d: x509.load_pem_x509_certificate(d).public_key(),
        lambda d: x509.load_der_x509_certificate(d).public_key(),
        lambda d: load_pem_public_key(d),
        lambda d: load_der_public_key(d),
        lambda d: load_ssh_public_key(d),
    ):
        try:
            return loader(data)
        except Exception:
            continue
    return None

# ---------------- auditar UM objeto de chave publica ----------------
def audit_single(pub):
    """Retorna (resumo:str, findings:list[(nivel, texto)]). nivel in {'VULN','OK','INFO'}."""
    if isinstance(pub, rsa.RSAPublicKey):
        pn = pub.public_numbers(); N, e = pn.n, pn.e
        bits = N.bit_length()
        findings = []
        for det, tag in [(det_fermat(N), "FERMAT"), (det_modM(N), "MOD-M"), (det_roca(N), "ROCA")]:
            if det[0]:
                findings.append(("VULN", f"{tag}: {det[2]}"))
        w = det_wiener(e, N)
        if w[0]:
            findings.append(("VULN", w[1]))
        if bits < 2048:
            findings.append(("INFO", f"tamanho {bits} bits < 2048: abaixo do recomendado atual."))
        if not any(f[0] == "VULN" for f in findings):
            findings.insert(0, ("OK", f"RSA {bits} bits: nenhuma classe fraca conhecida (Fermat/mod-M/ROCA/Wiener)."))
        return (f"RSA {bits}-bit (e={e})", findings)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        name = _CURVE_MAP.get(pub.curve.name, pub.curve.name)
        std = pub.curve.name in _STD_CURVES
        findings = []
        if std:
            findings.append(("OK", f"curva padrao {name}, ponto valido (validado pelo parser)."))
        else:
            findings.append(("VULN", f"curva NAO-padrao '{pub.curve.name}': risco de parametros fracos."))
        findings.append(("INFO", "o risco alto de ECC e' reuso de nonce em assinaturas — audite com ecc_audit.py 'sigs'."))
        return (f"EC {name}", findings)
    return ("chave nao suportada", [("INFO", "tipo de chave nao reconhecido.")])

def audit_bytes(data):
    """Para a interface web: recebe bytes de um PEM/DER/SSH, retorna (resumo, findings) ou None."""
    pub = _load_pubkey_from_bytes(data)
    if pub is None:
        return None
    return audit_single(pub)

# ---------------- CLI: arquivos/pastas ----------------
def load_keys(path):
    out = []
    with open(path, "rb") as f:
        data = f.read()
    pub = _load_pubkey_from_bytes(data)
    if pub is None:
        return out
    if isinstance(pub, rsa.RSAPublicKey):
        n_ = pub.public_numbers(); out.append(dict(src=path, kind="rsa", n=n_.n, e=n_.e, pub=pub))
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        out.append(dict(src=path, kind="ec", pub=pub))
    return out

def audit_paths(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for ext in ("*.pem", "*.crt", "*.cer", "*.der", "*.key", "*.pub", "*"):
                files += glob.glob(os.path.join(p, ext))
        else:
            files.append(p)
    files = sorted(set(f for f in files if os.path.isfile(f)))

    keys = []
    for f in files:
        try: keys += load_keys(f)
        except Exception: pass

    print(f"=== HonestKeyAudit — {len(keys)} chave(s) lida(s) de {len(files)} arquivo(s) ===\n")
    rsa_moduli = []; nvuln = 0
    for k in keys:
        resumo, findings = audit_single(k["pub"])
        vuln = any(f[0] == "VULN" for f in findings)
        if vuln: nvuln += 1
        mark = "VULNERAVEL" if vuln else "ok"
        print(f"  [{resumo}] {os.path.basename(k['src'])}: {mark}")
        for lvl, txt in findings:
            if lvl != "OK" or not vuln:
                print(f"        - {txt}")
        if k["kind"] == "rsa":
            rsa_moduli.append((k["src"], k["n"]))

    if len(rsa_moduli) >= 2:
        Ns = [n for _, n in rsa_moduli]
        bg = det_batch_gcd(Ns)
        shared = [rsa_moduli[i][0] for i, b in enumerate(bg) if b[0]]
        print()
        if shared:
            print(f"  [BATCH-GCD] FATOR COMPARTILHADO em {len(shared)} chave(s): "
                  f"{', '.join(os.path.basename(s) for s in shared)} — PRNG fraco, chaves quebraveis.")
            nvuln += 1
        else:
            print(f"  [BATCH-GCD] {len(Ns)} moduli RSA: nenhum fator compartilhado.")

    print(f"\n=== {nvuln} problema(s) em {len(keys)} chave(s) ===")
    return nvuln

def main():
    if len(sys.argv) < 2:
        print("uso: python src/keyaudit.py <arquivo-ou-pasta> [...]"); sys.exit(2)
    audit_paths(sys.argv[1:])

if __name__ == "__main__":
    main()
