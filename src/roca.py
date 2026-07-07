"""
Detector ROCA de verdade (CVE-2017-15361) — o "Return of Coppersmith's Attack".
===============================================================================
Nemec, Sys, Svenda, Klinec, Matyas (ACM CCS 2017). A RSALib da Infineon gera
primos da forma  p = k*M + (65537^a mod M),  com M um primorial. Isso deixa uma
assinatura detectavel SO' a partir do N publico:

  para todo primo pr que divide M,  N mod pr  esta' no subgrupo gerado por 65537.

Um N aleatorio cai fora desse subgrupo para algum pr com altissima probabilidade;
uma chave ROCA passa em TODOS. Chaves ROCA sao fatoraveis (Coppersmith) e afetaram
bilhoes de dispositivos (eIDs, TPMs, YubiKeys). Este e' o detector que deu
visibilidade mundial ao paper — e um marcador forte para o auditor.
"""
from functools import reduce

# Conjunto de primos-marcadores (como no detector de referencia crocs-muni/roca).
ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
               67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
               137, 139, 149, 151, 157, 163, 167]

def _subgroup(g, prime):
    """Subgrupo multiplicativo gerado por g modulo prime."""
    s = set(); x = 1 % prime
    for _ in range(prime):
        if x in s: break
        s.add(x); x = (x * g) % prime
    return s

_SUBGROUPS = {pr: _subgroup(65537 % pr, pr) for pr in ROCA_PRIMES}

def det_roca(N):
    """Retorna (vulneravel, score, detalhe). Vulneravel sse N mod pr esta' no
    subgrupo de 65537 para TODOS os primos-marcadores."""
    for pr in ROCA_PRIMES:
        if (N % pr) not in _SUBGROUPS[pr]:
            return (False, 0.0, "nao-ROCA (residuo fora do subgrupo de 65537).")
    return (True, 1.0,
            "ROCA (CVE-2017-15361): N tem a estrutura da RSALib/Infineon — chave FATORAVEL (Coppersmith).")

def _M():
    return reduce(lambda a, b: a * b, ROCA_PRIMES)

def selftest():
    import random
    r = random.Random(7); M = _M()
    # POSITIVO: N com a estrutura de residuo ROCA exata (65537^s mod M)
    pos_ok = all(det_roca(pow(65537, r.randrange(2, M), M))[0] for _ in range(20))
    # NEGATIVO: N aleatorios nao devem ser marcados (zero falso-positivo)
    fp = sum(1 for _ in range(3000) if det_roca(r.randrange(2**255, 2**256))[0])
    L = []
    L.append("="*66); L.append("AUTOTESTE — detector ROCA (CVE-2017-15361)"); L.append("="*66)
    L.append(f"  POSITIVO (estrutura ROCA):   {'detectado' if pos_ok else 'FALHOU'}  (esperado: detectado)")
    L.append(f"  NEGATIVO (3000 N aleatorios): {fp} falso-positivo(s)  (esperado: 0)")
    L.append("  => DETECTOR VALIDO" if (pos_ok and fp == 0) else "  => ALERTA: revisar.")
    return "\n".join(L), (pos_ok and fp == 0)

if __name__ == "__main__":
    txt, ok = selftest(); print(txt)
