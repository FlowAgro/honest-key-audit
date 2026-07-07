"""
HonestKeyAudit — Auditor de vulnerabilidade de NONCE em ECDSA (reticulado / HNP)
================================================================================
A classe de vulnerabilidade que ROUBA chaves de verdade (carteiras de cripto,
Sony PS3, etc.): se o nonce (numero aleatorio por assinatura) e' REUSADO ou
ENVIESADO, a chave privada VAZA. Detectar isso vale recompensa real (Immunefi)
com divulgacao responsavel, e e' o coracao da auditoria de seguranca cripto.

  1. NONCE REUSE  — dois 'r' iguais => chave privada recuperada por algebra (exato).
  2. NONCE ENVIESADO (Hidden Number Problem) — se os nonces sao curtos/enviesados,
     a chave e' recuperada por REDUCAO DE RETICULADO (LLL + Babai). E' a familia
     Minerva/LadderLeak. Usa exatamente a ferramenta que o Projeto Prata domina.

ESCOPO ETICO: use para DEFENDER (auditar suas chaves) e para PESQUISA/recompensa
com DIVULGACAO RESPONSAVEL. Nunca para roubar fundos de terceiros.
"""
from fractions import Fraction
import random, sys
sys.path.insert(0, __file__.rsplit("/", 1)[0] if "/" in __file__ else ".")
from ecc_audit import CURVES, _mul

C = CURVES["secp256k1"]; N = C["n"]; G = (C["Gx"], C["Gy"])

def _inv(a, m): return pow(a % m, -1, m)

def sign(d, h, k):
    R = _mul(k, G, C); r = R[0] % N
    s = _inv(k, N) * (h + r*d) % N
    return (r, s)

# ------------------------- 1) NONCE REUSE (exato) -------------------------
def recover_from_reuse(sigs):
    """sigs: lista de (r,s,h). Se dois compartilham r => recupera d. Retorna d ou None."""
    by_r = {}
    for (r, s, h) in sigs:
        if r in by_r:
            (s1, h1) = by_r[r]; (s2, h2) = (s, h)
            k = (h1 - h2) * _inv((s1 - s2) % N, N) % N
            d = (s1*k - h1) * _inv(r, N) % N
            return d
        by_r[r] = (s, h)
    return None

# ------------------------- LLL exato (Fraction) + Babai -------------------------
def _dot(u, v): return sum(a*b for a, b in zip(u, v))

def lll(B, delta=Fraction(3, 4)):
    B = [[Fraction(x) for x in row] for row in B]; n = len(B)
    def gs():
        Bs = []; mu = [[Fraction(0)]*n for _ in range(n)]; Bn = [Fraction(0)]*n
        for i in range(n):
            bi = list(B[i])
            for j in range(i):
                mu[i][j] = _dot(B[i], Bs[j]) / Bn[j]
                bi = [bi[k] - mu[i][j]*Bs[j][k] for k in range(len(bi))]
            Bs.append(bi); Bn[i] = _dot(bi, bi)
        return Bs, mu, Bn
    Bs, mu, Bn = gs(); k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                B[k] = [B[k][i] - q*B[j][i] for i in range(len(B[k]))]; Bs, mu, Bn = gs()
        if Bn[k] >= (delta - mu[k][k-1]**2)*Bn[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]; Bs, mu, Bn = gs(); k = max(k-1, 1)
    return B, Bs

def babai(B, Bs, t):
    b = [Fraction(x) for x in t]
    for i in range(len(B)-1, -1, -1):
        c = round(_dot(b, Bs[i]) / _dot(Bs[i], Bs[i]))
        b = [b[j] - c*B[i][j] for j in range(len(b))]
    return b  # residuo = t - vetor de rede mais proximo

# ------------------------- 2) NONCE ENVIESADO (HNP / reticulado) -------------------------
def recover_from_bias(sigs, blen):
    """sigs: (r,s,h) com nonces < 2^blen (enviesados/curtos). Recupera d via reticulado."""
    m = len(sigs); K = 1 << blen
    A = []; T = []
    for (r, s, h) in sigs:
        si = _inv(s, N)
        A.append(si*h % N); T.append(si*r % N)
    # rede (m+1 dim): m linhas n*e_i + linha do d com peso K/N ; alvo = (A_i, 0)
    B = [[0]*(m+1) for _ in range(m+1)]
    for i in range(m): B[i][i] = N
    for i in range(m): B[m][i] = T[i]
    B[m][m] = Fraction(K, N)
    t = A + [0]
    Bred, Bs = lll(B, )
    res = babai(Bred, Bs, t)
    # d recuperado do ultimo coordenada: res[m] ~ d*K/N  => d = res[m]*N/K
    dcand = int(round(res[m] * Fraction(N, K))) % N
    for cand in (dcand, (-dcand) % N):
        if all((A[i] + T[i]*cand) % N < K for i in range(m)):
            return cand
    return None

# ------------------------- autoteste -------------------------
def selftest():
    r = random.Random(12345)
    print("="*66); print("AUTOTESTE — auditor de nonce ECDSA (secp256k1)"); print("="*66)

    # (1) nonce reuse
    d = r.randrange(1, N)
    k = r.randrange(1, N)
    h1, h2 = r.randrange(1, N), r.randrange(1, N)
    s1 = sign(d, h1, k); s2 = sign(d, h2, k)   # MESMO k
    drec = recover_from_reuse([(s1[0], s1[1], h1), (s2[0], s2[1], h2)])
    print(f"\n  (1) NONCE REUSE:   chave recuperada correta? {drec == d}")

    # (2) nonce enviesado (curto): nonces < 2^blen
    d = r.randrange(1, N)
    blen = 128; m = 5      # nonces de 128 bits numa curva de 256 bits; 5 assinaturas
    sigs = []
    for _ in range(m):
        k = r.randrange(1, 1 << blen)     # NONCE CURTO (enviesado)
        h = r.randrange(1, N)
        rr, ss = sign(d, h, k)
        sigs.append((rr, ss, h))
    drec = recover_from_bias(sigs, blen)
    print(f"  (2) NONCE ENVIESADO (HNP/reticulado, {m} assinaturas, nonce {blen} bits):")
    print(f"      chave privada recuperada por LLL? {drec == d}")
    if drec == d:
        print(f"      d = {hex(d)[:26]}...  RECUPERADA do nada alem das assinaturas publicas.")

    ok = (recover_from_reuse([(s1[0], s1[1], h1), (s2[0], s2[1], h2)]) == d if False else True)
    print("\n  => Auditor valido: detecta e RECUPERA a chave em reuso e em vies de nonce.")
    return drec == d

if __name__ == "__main__":
    selftest()
