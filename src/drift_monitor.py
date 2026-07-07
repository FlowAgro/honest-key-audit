"""
HonestKeyAudit — Monitor de DRIFT de gerador (o motor do SaaS de QA continuo)
=============================================================================
O jeito CORRETO de auditar geradores (achado em src/provenance.py): nao testar
contra a teoria (o uniforme puro falso-positiva em OpenSSL, que restringe bits),
mas contra uma BASELINE de chaves confiaveis do MESMO gerador. Fluxo do produto:

  1. baseline(Ns_confiaveis)  -> fingerprint do gerador saudavel
  2. check_drift(fingerprint, Ns_novas) -> as chaves novas ainda batem? (drift?)

Alertar so' quando a populacao NOVA diverge da baseline. Isso pega:
  - troca/degradacao silenciosa do gerador (atualizacao ruim, HSM trocado),
  - contaminacao (chaves de outra origem misturadas — hardware falsificado),
  - deriva de entropia — SEM falso-positivo no gerador legitimo.

Testes de duas amostras (baseline vs novo), todos so' do N publico:
  - KS na fase de prata phi(N) (a lente do paper da Barreira),
  - KS no valor lider f=N/2^(bits-2) (restricoes de bits do gerador),
  - homogeneidade chi-quadrado de N mod m (vies modular).
Veredito: DRIFT se qualquer teste diverge (Bonferroni).
"""
import bisect, mpmath as mp
from sympy import isprime
from gen_anomaly import silver_phase, SMALL_PRIMES

def leading(N):
    # f = N/2^(bits-2) em [1,4); shift antes do float para nao estourar em chaves >=2048 bits
    b = N.bit_length(); shift = b - 54
    return (N >> shift)/float(2**52) if shift > 0 else N/float(2**(b-2))

def _ks_p_stat(D, en):
    x = (en + 0.12 + 0.11/en) * D
    s = mp.mpf(0)
    for k in range(1, 101):
        s += (-1)**(k-1) * mp.e**(-2*k*k*x*x)
    return float(min(max(2*s, mp.mpf(0)), mp.mpf(1)))

def two_sample_ks(a, b):
    a = sorted(a); b = sorted(b); na = len(a); nb = len(b)
    D = 0.0
    for x in sorted(set(a) | set(b)):
        Fa = bisect.bisect_right(a, x) / na
        Fb = bisect.bisect_right(b, x) / nb
        D = max(D, abs(Fa - Fb))
    en = (na*nb/(na+nb)) ** 0.5
    return D, _ks_p_stat(D, en)

def _chi2_sf(x, k):
    return float(mp.gammainc(mp.mpf(k)/2, mp.mpf(x)/2, mp.inf, regularized=True))

def residue_homogeneity(base, new, m):
    cb = [0]*m; cn = [0]*m
    for N in base: cb[N % m] += 1
    for N in new: cn[N % m] += 1
    idx = list(range(1, m)) if isprime(m) else list(range(m))
    nb = sum(cb[i] for i in idx); nn = sum(cn[i] for i in idx); tot = nb + nn
    if tot == 0: return (0.0, 1.0)
    chi2 = 0.0
    for i in idx:
        col = cb[i] + cn[i]
        for cnt, rowtot in ((cb[i], nb), (cn[i], nn)):
            exp = rowtot * col / tot
            if exp > 0: chi2 += (cnt - exp)**2 / exp
    return chi2, _chi2_sf(chi2, len(idx) - 1)

def baseline(Ns):
    """Fingerprint do gerador confiavel: amostras (p/ testes de 2 amostras) + PISO teorico
    do valor lider. Geradores FIPS/OpenSSL forcam os 2 bits altos => f = N/2^(bits-2) >= 2.25,
    EXATO. Se a baseline respeita isso, temos um piso de suporte com CERTEZA (sem falso-pos.)."""
    lead = [leading(N) for N in Ns]
    floor = 2.25 if min(lead) >= 2.25 else None  # piso teorico so' se o gerador o respeita
    return dict(n=len(Ns), phi=[silver_phase(N) for N in Ns], lead=lead, Ns=list(Ns), floor=floor)

def check_drift(fp, new_Ns, alpha=0.01):
    # (1) SUPORTE (so' lado baixo, piso teorico): f < 2.25 e' IMPOSSIVEL p/ gerador FIPS/OpenSSL,
    #     entao cada chave nova abaixo do piso e' PROVA de outra origem (contaminacao/falsificacao),
    #     chave-a-chave, com zero falso-positivo. (O lado alto vai a 4 continuamente — sem piso.)
    outliers = [N for N in new_Ns if fp["floor"] is not None and leading(N) < fp["floor"]]

    # (2) testes distribucionais de 2 amostras (drift global mais sutil)
    tests = []
    Dp, pp = two_sample_ks(fp["phi"], [silver_phase(N) for N in new_Ns])
    tests.append(("fase-prata phi(N)", Dp, pp))
    Dl, pl = two_sample_ks(fp["lead"], [leading(N) for N in new_Ns])
    tests.append(("valor lider f", Dl, pl))
    for m in SMALL_PRIMES:
        c, p = residue_homogeneity(fp["Ns"], new_Ns, m)
        tests.append((f"N mod {m}", c, p))
    minp = min(t[2] for t in tests); thr = alpha / len(tests)
    drift = (minp < thr) or (len(outliers) > 0)
    return dict(tests=tests, min_p=minp, threshold=thr, n_out=len(outliers),
                n_new=len(new_Ns), drift=drift)

def _report(title, rep):
    worst = sorted(rep["tests"], key=lambda t: t[2])[:2]
    tag = "*** DRIFT DETECTADO ***" if rep["drift"] else "sem drift (bate com a baseline)"
    print(f"  {title:<44} {tag}")
    if rep["n_out"] > 0:
        print(f"      SUPORTE: {rep['n_out']}/{rep['n_new']} chaves FORA da faixa do gerador "
              f"confiavel = outra origem (certeza)  <==")
    for nome, stat, p in worst:
        flag = "  <==" if p < rep["threshold"] else ""
        print(f"      {nome:<20} stat={stat:8.2f}  p={p:.2e}{flag}")

def selftest():
    from cryptography.hazmat.primitives.asymmetric import rsa
    import random
    from sympy import nextprime
    BITS = 1024

    def openssl(n):
        return [rsa.generate_private_key(public_exponent=65537, key_size=BITS)
                .private_numbers().public_numbers.n for _ in range(n)]
    r = random.Random(7)
    def naive(n):
        h = BITS//2
        return [int(nextprime(r.randrange(2**(h-1), 2**h))) *
                int(nextprime(r.randrange(2**(h-1), 2**h))) for _ in range(n)]

    print("="*68); print("MONITOR DE DRIFT — baseline = gerador OpenSSL confiavel"); print("="*68)
    base = openssl(200)
    fp = baseline(base)
    print(f"\nbaseline: {fp['n']} chaves OpenSSL confiaveis.\n")

    same = openssl(200)                      # mesmo gerador -> SEM drift
    diff = naive(200)                        # gerador totalmente diferente -> DRIFT
    contam = openssl(160) + naive(40)        # 20% contaminado -> DRIFT (supply-chain)

    r_same = check_drift(fp, same); r_diff = check_drift(fp, diff); r_cont = check_drift(fp, contam)
    _report("lote novo do MESMO gerador OpenSSL:", r_same)
    _report("lote de gerador DIFERENTE (ingenuo):", r_diff)
    _report("lote CONTAMINADO (80% OpenSSL + 20% outro):", r_cont)

    ok = (not r_same["drift"]) and r_diff["drift"] and r_cont["drift"]
    print("\n=> " + ("MOTOR VALIDO: sem alarme no gerador legitimo; DRIFT detectado em troca de "
                     "gerador E em contaminacao parcial. E' o SaaS de monitoramento continuo."
                     if ok else "revisar (sensibilidade da baseline)."))
    return ok

if __name__ == "__main__":
    selftest()
