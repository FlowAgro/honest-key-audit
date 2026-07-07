"""
Projeto Prata — Auditor de chaves ECC (trilha defensiva, complemento do src/56 RSA)
====================================================================================
Extensao ECC do auditor honesto. Espirito anti-ROCA / "Mining your Ps and Qs":
DESCobrir chaves/assinaturas fracas CONHECIDAS para PROTEGER o dono. NAO ataca
chave de terceiro — roda sobre chaves proprias, sinteticas ou datasets publicos.

HONESTIDADE DE ESCOPO:
  Estes detectores acham classes fracas CONHECIDAS de ECC. Eles NAO quebram ECC
  forte com curva padrao e nonce aleatorio. O valor e' duplo:
    - audit : achar chaves/assinaturas ja' emitidas que cairam numa classe fraca;
    - guard : garantir que uma chave/assinatura nova NAO cai em nenhuma delas.

Deteccoes de CHAVE PUBLICA:
  1. ON-CURVE      — o ponto publico esta' mesmo na curva declarada? (invalid-curve)
  2. CURVA PADRAO  — a curva e' uma curva padrao conhecida-boa? (parametros nao-padrao
                     = risco de backdoor/curva fraca, estilo alerta pos-Dual_EC).
  3. SUBGRUPO      — o ponto tem ordem = n (nao esta' num subgrupo pequeno / cofator)?
  4. ANOMALA       — #E == p (n*h == p) => ataque de Smart (transferencia aditiva).
  5. MOV/EMBEDDING — grau de mergulho pequeno (n | p^k-1, k pequeno) => ataque de pareamento.

Deteccoes de ASSINATURA ECDSA:
  6. NONCE REUSE   — dois 'r' iguais com a mesma chave => nonce repetido => a chave
                     privada VAZA (classe Sony PS3 / muitas carteiras). Detectado e,
                     no modo guard, demonstrado por que e' fatal (recuperacao de d).

Uso (CLI):
  python src/61_ecc_audit.py selftest
  python src/61_ecc_audit.py pubkey <curva> <Px_hex> <Py_hex>
  python src/61_ecc_audit.py sigs   <arquivo_sigs.txt>   # linhas: r_hex s_hex z_hex
"""
import os, sys, argparse
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OUTDIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(OUTDIR, exist_ok=True)

# ============================================================ registro de curvas padrao
# (nome: p, a, b, Gx, Gy, n, h) — curvas conhecidas-boas.
CURVES = {
    "P-256": dict(
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        h=1),
    "secp256k1": dict(
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        a=0, b=7,
        Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
        n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
        h=1),
}

# ============================================================ aritmetica de curva (Weierstrass)
def _on_curve(P, C):
    if P is None: return True  # ponto no infinito
    x, y = P; p = C["p"]
    return (y*y - (x*x*x + C["a"]*x + C["b"])) % p == 0

def _add(P, Q, C):
    if P is None: return Q
    if Q is None: return P
    p = C["p"]; (x1,y1),(x2,y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        m = (3*x1*x1 + C["a"]) * pow(2*y1, -1, p) % p
    else:
        m = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p
    return (x3, y3)

def _mul(k, P, C):
    R = None; Q = P; k0 = k  # nao reduzir k: queremos a ordem exata do ponto
    while k0 > 0:
        if k0 & 1: R = _add(R, Q, C)
        Q = _add(Q, Q, C); k0 >>= 1
    return R

# ============================================================ detectores de chave publica
def det_on_curve(P, C):
    ok = _on_curve(P, C)
    return (not ok, 1.0 if not ok else 0.0,
            "ponto NAO esta' na curva (invalid-curve: risco de vazamento por curva invalida)."
            if not ok else "ponto esta' na curva.")

def det_standard_curve(name):
    known = name in CURVES
    return (not known, 1.0 if not known else 0.0,
            f"curva '{name}' NAO e' padrao conhecida (risco de parametros fracos/backdoor)."
            if not known else f"curva padrao conhecida: {name}.")

def det_subgroup(P, C):
    """ordem do ponto = n? n*P deve ser o infinito; e P != infinito, != baixa ordem."""
    if P is None:
        return (True, 1.0, "ponto e' o infinito (ordem 1) — chave degenerada.")
    nP = _mul(C["n"], P, C)
    if nP is not None:
        return (True, 1.0, "n*P != infinito: ponto FORA do subgrupo de ordem n (subgrupo pequeno).")
    # cofator > 1: checa que h*P != infinito garante ordem exatamente n (para h=1, trivial)
    if C["h"] > 1:
        hP = _mul(C["h"], P, C)
        if hP is None:
            return (True, 1.0, "h*P = infinito: ponto de ordem <= h (subgrupo pequeno).")
    return (False, 0.0, "ponto tem ordem n (subgrupo correto).")

def det_anomalous(C):
    """#E == p  <=>  n*h == p  =>  curva anomala (ataque de Smart, log discreto em tempo poly)."""
    anom = (C["n"] * C["h"] == C["p"])
    return (anom, 1.0 if anom else 0.0,
            "curva ANOMALA (#E == p): vulneravel ao ataque de Smart." if anom
            else "nao-anomala (#E != p).")

def det_mov(C, kmax=40):
    """grau de mergulho pequeno: menor k com n | p^k - 1. k pequeno => ataque MOV/pareamento."""
    n = C["n"]; pk = C["p"] % n
    for k in range(1, kmax+1):
        if pk == 1:
            return (True, 1.0, f"grau de mergulho k={k} <= {kmax}: vulneravel a MOV/pareamento.")
        pk = (pk * C["p"]) % n
    return (False, 0.0, f"grau de mergulho > {kmax}: resistente a MOV.")

def audit_pubkey(name, Px, Py):
    C = CURVES.get(name)
    problems = []
    std = det_standard_curve(name)
    if std[0]: problems.append(("CURVA-NAO-PADRAO", std))
    if C is None:
        return dict(vulnerable=True, problems=problems,
                    note="curva desconhecida: sem parametros para checar on-curve/subgrupo.")
    P = (Px, Py)
    for tag, d in [("ON-CURVE", det_on_curve(P, C)),
                   ("SUBGRUPO", det_subgroup(P, C)),
                   ("ANOMALA", det_anomalous(C)),
                   ("MOV", det_mov(C))]:
        if d[0]: problems.append((tag, d))
    return dict(vulnerable=len(problems) > 0, problems=problems, note="")

# ============================================================ detector de assinatura ECDSA
def audit_ecdsa(sigs, n):
    """sigs: lista de (r, s, z). Detecta NONCE REUSE (r repetido) e recupera d p/ provar."""
    by_r = {}
    for i, (r, s, z) in enumerate(sigs):
        by_r.setdefault(r, []).append((i, s, z))
    findings = []
    for r, group in by_r.items():
        if len(group) >= 2:
            (i1, s1, z1), (i2, s2, z2) = group[0], group[1]
            try:
                k = (z1 - z2) * pow((s1 - s2) % n, -1, n) % n
                d = (s1 * k - z1) * pow(r, -1, n) % n
                proof = f"chave privada d recuperada = {hex(d)}"
            except Exception:
                proof = "r repetido (recuperacao exige s1!=s2)"
            findings.append((True, 1.0,
                f"NONCE REUSE em r={hex(r)} (assinaturas #{i1},#{i2}): a chave privada VAZA. {proof}. "
                f"AÇÃO: rotacionar a chave IMEDIATAMENTE."))
    if not findings:
        return [(False, 0.0, f"{len(sigs)} assinaturas: nenhum nonce repetido detectado.")]
    return findings

# ============================================================ autoteste
def selftest():
    L = []
    def line(s=""): L.append(s)
    line("="*70); line("AUTOTESTE — auditor ECC defensivo"); line("="*70)

    # (1) chave valida: gerador de P-256 (esta' na curva, subgrupo n, curva padrao)
    C = CURVES["P-256"]; G = (C["Gx"], C["Gy"])
    rep = audit_pubkey("P-256", *G)
    line(f"  [1] P-256 gerador (chave BOA):      vulneravel={rep['vulnerable']}  (esperado False)")
    for t,d in rep["problems"]: line(f"        - {t}: {d[2]}")

    # (2) ponto FORA da curva (invalid-curve): Gy+1
    rep = audit_pubkey("P-256", C["Gx"], (C["Gy"]+1) % C["p"])
    line(f"  [2] P-256 ponto off-curve (RUIM):   vulneravel={rep['vulnerable']}  (esperado True)")
    for t,d in rep["problems"]: line(f"        - {t}: {d[2]}")

    # (3) curva desconhecida/nao-padrao
    rep = audit_pubkey("MinhaCurvaCaseira", 1, 2)
    line(f"  [3] curva nao-padrao (RUIM):        vulneravel={rep['vulnerable']}  (esperado True)")
    for t,d in rep["problems"]: line(f"        - {t}: {d[2]}")

    # (4) ECDSA nonce reuse: forja duas assinaturas com o mesmo k e a mesma chave d
    n = C["n"]
    import random; rng = random.Random(31415)
    d = rng.randrange(1, n); k = rng.randrange(1, n)
    R = _mul(k, G, C); r = R[0] % n
    z1 = rng.randrange(1, n); z2 = rng.randrange(1, n)
    kinv = pow(k, -1, n)
    s1 = kinv * (z1 + r*d) % n
    s2 = kinv * (z2 + r*d) % n
    finds = audit_ecdsa([(r, s1, z1), (r, s2, z2)], n)
    ok_rec = any(("d recuperada" in f[2]) for f in finds)
    # confere que d recuperado bate com o verdadeiro
    recovered_ok = False
    if ok_rec:
        # reexecuta a formula para conferir
        kk = (z1 - z2) * pow((s1 - s2) % n, -1, n) % n
        dd = (s1*kk - z1) * pow(r, -1, n) % n
        recovered_ok = (dd == d)
    line(f"  [4] ECDSA nonce reuse (FATAL):      detectado={finds[0][0]}  d_correto={recovered_ok}  (esperado True/True)")
    line(f"        - {finds[0][2][:88]}...")

    line("")
    passed = (not audit_pubkey('P-256',*G)['vulnerable']
              and audit_pubkey('P-256',C['Gx'],(C['Gy']+1)%C['p'])['vulnerable']
              and finds[0][0] and recovered_ok)
    line("  => FERRAMENTA VALIDA" if passed else "  => ALERTA: revisar detectores.")
    return "\n".join(L), passed

# ============================================================ CLI
def _hx(s): s=s.strip(); return int(s,16) if s.lower().startswith("0x") else int(s,16)

def main():
    ap = argparse.ArgumentParser(description="Auditor ECC defensivo (chaves e assinaturas).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    pk = sub.add_parser("pubkey"); pk.add_argument("curva"); pk.add_argument("Px"); pk.add_argument("Py")
    sg = sub.add_parser("sigs"); sg.add_argument("file"); sg.add_argument("--curve", default="P-256")
    a = ap.parse_args()

    if a.cmd == "selftest":
        txt, ok = selftest(); print(txt)
        with open(os.path.join(OUTDIR, "61_ecc_audit.txt"), "w", encoding="utf-8") as f: f.write(txt)
    elif a.cmd == "pubkey":
        rep = audit_pubkey(a.curva, _hx(a.Px), _hx(a.Py))
        print(f"=== AUDIT pubkey em {a.curva} ===")
        if rep["vulnerable"]:
            print("  VULNERAVEL:")
            for t,d in rep["problems"]: print(f"    {t}: {d[2]}")
            if rep["note"]: print(f"    nota: {rep['note']}")
        else:
            print("  OK: nenhuma classe fraca conhecida detectada.")
    elif a.cmd == "sigs":
        n = CURVES[a.curve]["n"]; sigs = []
        with open(a.file) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"): continue
                r,s,z = ln.split()
                sigs.append((int(r,16), int(s,16), int(z,16)))
        for v,sc,msg in audit_ecdsa(sigs, n):
            print(("  [VULNERAVEL] " if v else "  [ok] ") + msg)

if __name__ == "__main__":
    main()
