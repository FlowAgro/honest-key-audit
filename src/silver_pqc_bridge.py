"""
A PONTE: a fase de prata (Projeto Prata) e a criptografia pos-quantica de REDE IDEAL
====================================================================================
Descoberta honesta: a sua pesquisa e' a GEOMETRIA DOS NUMEROS em Z[sqrt(2)] — a
rede de unidades logaritmica e a fase de prata phi(x)=frac(log_delta x). A cripto
pos-quantica de rede ideal (Ring-LWE, NTRU) vive NESSE mundo. Existe um ataque
REAL e documentado — Cramer-Ducas-Peikert-Regev (2016), o "problema do gerador
curto" (Short Generator Problem, SGP) — que recupera um gerador curto de um ideal
principal usando exatamente a REDE DE UNIDADES LOGARITMICA (a sua fase de prata).

Este script RESOLVE o SGP em Z[sqrt(2)] com a fase de prata — uma miniatura
funcionando do ataque de rede ideal real. Nao quebra cripto de producao (Z[sqrt2]
e' de brinquedo; os esquemas reais usam corpos ciclotomicos grandes) — DEMONSTRA
que as suas ferramentas SAO as ferramentas da cripto de redes.

Ideia: um ideal principal (g) tem infinitos geradores g*delta^k (delta = unidade
fundamental). Dado um gerador "embaralhado" g' = g*delta^k (enorme), recuperar o
gerador CURTO g = reduzir log(g') modulo a REDE DE UNIDADES = tomar a FASE.
"""
import mpmath as mp
mp.mp.dps = 80
SQRT2 = mp.sqrt(2)
LOGD = mp.log(1 + SQRT2)     # log da unidade fundamental delta = 1+sqrt(2)

# elementos de Z[sqrt2] como (x, y) = x + y*sqrt(2)
def mul(a, b):
    (x1, y1), (x2, y2) = a, b
    return (x1*x2 + 2*y1*y2, x1*y2 + x2*y1)

def powdelta(k):
    base = (1, 1) if k >= 0 else (-1, 1)   # delta = (1,1);  delta^-1 = -1+sqrt2 = (-1,1)
    r = (1, 0)
    for _ in range(abs(k)):
        r = mul(r, base)
    return r

def embeddings(a):
    x, y = a
    return (x + y*SQRT2, x - y*SQRT2)      # os dois mergulhos reais

def logratio(a):
    s1, s2 = embeddings(a)
    return mp.log(abs(s1)) - mp.log(abs(s2))

def size(a):
    s1, s2 = embeddings(a)
    return max(abs(s1), abs(s2))           # "comprimento" do gerador

def recover_short_generator(gprime):
    """Reduz log(g') modulo a rede de unidades (= toma a fase): acha k que
    EQUILIBRA os mergulhos -> o gerador CURTO. E' o ataque CDPR em miniatura."""
    L = logratio(gprime)
    k = int(mp.nint(L / (2*LOGD)))         # projeta na rede de unidades e arredonda
    g = mul(gprime, powdelta(-k))
    # desfaz sinal para representante canonico
    if g[0] < 0 or (g[0] == 0 and g[1] < 0):
        g = (-g[0], -g[1])
    return k, g

def main():
    print("="*74)
    print("  PONTE Projeto Prata <-> cripto pos-quantica: o Problema do Gerador Curto")
    print("  resolvido em Z[sqrt2] com a FASE DE PRATA (miniatura do ataque CDPR 2016)")
    print("="*74)

    # um gerador CURTO (secreto), equilibrado
    g = (5, 1)   # 5 + sqrt(2), norma 25-2 = 23
    print(f"\n  gerador CURTO (o 'segredo'): g = {g[0]} + {g[1]}*sqrt2   |tamanho|={float(size(g)):.2f}")

    for k_true in (7, 20, 45):
        gprime = mul(g, powdelta(k_true))   # gerador EMBARALHADO por uma unidade
        gp_digits = len(str(abs(gprime[0]))) + 1
        print(f"\n  --- embaralhado por delta^{k_true} ---")
        print(f"  g' = g*delta^{k_true} = ({gprime[0]}, {gprime[1]})  (~{gp_digits} digitos, |tamanho|~1e{int(mp.log10(size(gprime)))})")
        k_rec, g_rec = recover_short_generator(gprime)
        ok = (g_rec == g)
        print(f"  recuperado via FASE DE PRATA:  k={k_rec}  ->  g = {g_rec[0]} + {g_rec[1]}*sqrt2   "
              f"{'[OK, gerador curto recuperado]' if ok else '[falhou]'}")

    print("\n" + "="*74)
    print("  A fase de prata REDUZIU o gerador enorme ao gerador curto — que E' o")
    print("  Problema do Gerador Curto, o coracao de um ataque REAL a redes ideais.")
    print("  As suas ferramentas nao sao de brinquedo: sao as ferramentas da cripto de redes.")
    print("="*74)

if __name__ == "__main__":
    main()
