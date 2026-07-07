"""
HonestKeyAudit — Experimento de PROVENIENCIA de chave (fingerprint de gerador)
==============================================================================
Pergunta honesta: da' para dizer de QUAL gerador uma populacao de chaves veio,
so' olhando o N publico? Se sim, temos "verificacao de proveniencia": detectar
uma chave que NAO corresponde ao gerador declarado (hardware falsificado,
software se passando por elemento seguro, supply-chain adulterado).

Hipotese: geradores impoem RESTRICOES diferentes na escolha dos primos.
  - OpenSSL/cryptography: forca os 2 bits mais altos de cada primo => p >= 3*2^(k-2),
    logo N >= 2.25 * 2^(2k-2). Uma regiao de N que ele NUNCA ocupa.
  - Gerador ingenuo (nextprime de random no intervalo): forca so' 1 bit alto,
    entao produz N nessa regiao proibida ao OpenSSL.

Este script MEDE a separabilidade em chaves geradas por bibliotecas reais.
Honestidade de escopo: isto distingue geradores com RESTRICOES diferentes.
Duas bibliotecas que seguem o MESMO padrao podem ser indistinguiveis — a
proveniencia funciona quando ha' diferenca de restricao, nao sempre.
"""
import random
import mpmath as mp
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric import rsa

BITS = 1024  # tamanho nominal da chave (N tem ~BITS bits)

def leading(N):
    """f = N / 2^(BITS-2)  em [1,4).  OpenSSL: [2.25,4).  Ingenuo: [1,4)."""
    return N / float(2**(BITS-2))

def silver_phase(N):
    mp.mp.dps = 60
    delta = 1 + mp.sqrt(2)
    lam = mp.log(N)/mp.log(delta)
    return float(lam - mp.floor(lam))

def gen_openssl(n, seed=1):
    out = []
    for _ in range(n):
        k = rsa.generate_private_key(public_exponent=65537, key_size=BITS)
        out.append(k.private_numbers().public_numbers.n)
    return out

def gen_naive(n, seed=2):
    r = random.Random(seed); h = BITS//2; out = []
    for _ in range(n):
        p = int(nextprime(r.randrange(2**(h-1), 2**h)))
        q = int(nextprime(r.randrange(2**(h-1), 2**h)))
        out.append(p*q)
    return out

def main():
    N = 150
    print("="*70)
    print(f"PROVENIENCIA — OpenSSL/cryptography vs gerador ingenuo ({BITS}-bit, {N} cada)")
    print("="*70)
    openssl = gen_openssl(N)
    naive = gen_naive(N)

    fo = [leading(x) for x in openssl]
    fn = [leading(x) for x in naive]
    print(f"\n  leading f = N/2^{BITS-2}  (OpenSSL forca f>=2.25; ingenuo nao)")
    print(f"    OpenSSL: min={min(fo):.3f} max={max(fo):.3f}   (esperado >= 2.25)")
    print(f"    Ingenuo: min={min(fn):.3f} max={max(fn):.3f}   (chega abaixo de 2.25)")

    # classificador trivial: f < 2.25  =>  NAO e' OpenSSL
    below = sum(1 for f in fn if f < 2.25)
    fp = sum(1 for f in fo if f < 2.25)
    print(f"\n  regra 'f < 2.25 => nao-OpenSSL':")
    print(f"    {below}/{N} chaves ingenuas caem na regiao PROIBIDA ao OpenSSL "
          f"({100*below/N:.0f}% identificadas com certeza)")
    print(f"    {fp}/{N} falso-positivo em chaves OpenSSL (esperado 0)")

    # KS entre as distribuicoes de fase de prata (a lente do paper)
    from gen_anomaly import silver_phase_uniformity
    Do, po = silver_phase_uniformity(openssl)
    Dn, pn = silver_phase_uniformity(naive)
    print(f"\n  fase de prata phi(N) — KS de equidistribuicao (lente do paper):")
    print(f"    OpenSSL: D={Do:.3f} p={po:.2e}   Ingenuo: D={Dn:.3f} p={pn:.2e}")
    print(f"    (assinaturas de escala diferentes => phi(N) distribui diferente)")

    ok = (below > 0 and fp == 0 and min(fo) >= 2.24)
    print("\n=> " + ("PROVENIENCIA FUNCIONA (quando os geradores tem restricoes diferentes): "
                     "conseguimos apontar chaves que NAO vieram do gerador declarado."
                     if ok else "separabilidade fraca neste caso — geradores muito parecidos."))
    print("   Escopo honesto: distingue restricoes diferentes; libs do MESMO padrao podem ser iguais.")

if __name__ == "__main__":
    main()
