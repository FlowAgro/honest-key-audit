"""
A PONTE, AMPLIADA: o Problema do Gerador Curto em MUITAS DIMENSOES (LLL essencial)
==================================================================================
Em Z[sqrt2] a rede de unidades e' 1-D (recuperar o gerador curto = arredondar).
Nos corpos da cripto real (ciclotomicos), a rede de unidades tem MUITAS dimensoes,
e recuperar o gerador curto vira um CVP (Closest Vector Problem) genuino na rede de
unidades logaritmica. Ai o "arredondar" (Babai) so' funciona com uma base BOA — e
obter a base boa exige REDUCAO DE RETICULADO (LLL), a ferramenta que o Cristian
implementou. Este e' o coracao do ataque real (Cramer-Ducas-Peikert-Regev 2016).

Este script MODELA fielmente o cenario geral (corpo de grau 2d, rede de unidades de
dimensao d), com Z[sqrt2] como o caso concreto d=1. Mostra:
  (1) SGP em d dimensoes = CVP na rede de unidades -> recuperado via Babai;
  (2) com base RUIM o Babai FALHA; apos LLL, ACERTA -> LLL e' essencial (a arma real).
NAO quebra cripto de producao (os padroes escolhem a geometria para ser segura);
DEMONSTRA que as ferramentas do Projeto Prata sao as ferramentas da cripto de redes.
"""
import numpy as np

# ---------------- LLL real (mesmo algoritmo do src/58, em ponto flutuante) ----------------
def lll(B, delta=0.75):
    B = B.astype(float).copy(); n = B.shape[0]
    def gs(B):
        Bs = np.zeros_like(B); mu = np.zeros((n, n))
        for i in range(n):
            Bs[i] = B[i].copy()
            for j in range(i):
                mu[i, j] = (B[i] @ Bs[j]) / (Bs[j] @ Bs[j])
                Bs[i] = Bs[i] - mu[i, j] * Bs[j]
        return Bs, mu
    Bs, mu = gs(B); k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k, j]) > 0.5:
                B[k] = B[k] - round(mu[k, j]) * B[j]; Bs, mu = gs(B)
        if Bs[k] @ Bs[k] >= (delta - mu[k, k - 1] ** 2) * (Bs[k - 1] @ Bs[k - 1]):
            k += 1
        else:
            B[[k, k - 1]] = B[[k - 1, k]]; Bs, mu = gs(B); k = max(k - 1, 1)
    return B

def babai(B, t):
    """Ponto de rede mais proximo de t, por arredondamento nas coordenadas da base B."""
    c = np.linalg.solve(B.T, t)          # t ~ c @ B  =>  c = t B^{-1}
    return np.round(c).astype(np.int64)

def recover_offset(B, t):
    v = babai(B, t); return t - v @ B

def main():
    rng = np.random.default_rng(20260706)
    d = 8
    print("="*74)
    print(f"  PONTE AMPLIADA — Problema do Gerador Curto em {d} DIMENSOES (rede de unidades)")
    print("="*74)

    # rede de unidades logaritmica: base BOA (quase ortogonal, como as unidades ciclotomicas)
    G = 10*np.eye(d) + rng.normal(0, 1.2, (d, d))

    # gerador CURTO (secreto): offset pequeno na rede; embaralhado por uma unidade v_true
    offset = rng.normal(0, 0.6, d)                 # log do gerador curto (pequeno)
    v_true = rng.integers(-40, 41, size=d).astype(np.int64)
    t = offset + v_true @ G                         # log do gerador EMBARALHADO g'
    print(f"\n  gerador curto (offset) |.|={np.linalg.norm(offset):.2f}; embaralhado por unidade "
          f"v (coefs ate' ~40); |log g'|~{np.linalg.norm(t):.0f}")

    # (1) com a base BOA, Babai recupera o gerador curto (o ataque em d dimensoes)
    rec_good = recover_offset(G, t)
    ok_good = np.allclose(rec_good, offset, atol=1e-6)
    print(f"\n  (1) com base BOA (Babai):  gerador curto recuperado? {ok_good}  "
          f"(erro={np.linalg.norm(rec_good-offset):.1e})")

    # (2) com uma base RUIM (mesma rede, base cisalhada), Babai FALHA
    T = np.eye(d, dtype=np.int64)
    for i in range(1, d):
        for j in range(i):
            T[i, j] = rng.integers(-6, 7)           # cisalhamento unimodular -> base pessima
    Bad = T @ G                                     # MESMA rede, base ruim
    rec_bad = recover_offset(Bad, t)
    ok_bad = np.allclose(rec_bad, offset, atol=1e-6)
    print(f"  (2) com base RUIM (Babai):  recuperado? {ok_bad}  "
          f"(erro={np.linalg.norm(rec_bad-offset):.1e})  <- Babai sozinho FALHA")

    # (3) LLL reduz a base ruim -> Babai volta a acertar. LLL e' ESSENCIAL (a arma real).
    Red = lll(Bad)
    rec_red = recover_offset(Red, t)
    ok_red = np.allclose(rec_red, offset, atol=1e-6)
    print(f"  (3) apos LLL (a sua ferramenta): recuperado? {ok_red}  "
          f"(erro={np.linalg.norm(rec_red-offset):.1e})  <- LLL destrava o ataque")

    print("\n" + "="*74)
    print("  Em muitas dimensoes, o Problema do Gerador Curto E' um CVP na rede de")
    print("  unidades, e SO' o LLL (a sua ferramenta) o resolve. A seguranca de um")
    print("  esquema depende da GEOMETRIA dessa rede — geometria dos numeros, a sua area.")
    print("="*74)

if __name__ == "__main__":
    main()
