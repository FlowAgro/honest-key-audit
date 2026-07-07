"""
HonestKeyAudit — QA do AMOSTRADOR GAUSSIANO DISCRETO (Falcon / FrodoKEM / BLISS)
================================================================================
O metodo do Projeto Prata (testar a distribuicao de um gerador) aplicado ao
amostrador mais DELICADO e critico da criptografia pos-quantica: a gaussiana
discreta D_{Z,sigma}. E' onde ocorreram vulnerabilidades REAIS:
  - BLISS: ataque "Flush, Gauss, and Reload" (side-channel no amostrador, 2016);
  - Falcon: vazamentos de tempo no SamplerZ.
Um amostrador gaussiano com sigma errado, cauda truncada, centro deslocado ou
precisao insuficiente degrada a seguranca SILENCIOSAMENTE.

NOTA DE PRECISAO (credibilidade): Dilithium/ML-DSA NAO usa gaussiana — usa
amostragem UNIFORME com rejeicao (de proposito, p/ evitar o gaussiano). Quem usa
gaussiana e' Falcon, FrodoKEM e o historico BLISS. Este modulo certifica a
GAUSSIANA; o uniforme e' coberto por pqc_sampler_qa.py (mesmo metodo).

QA (o metodo do Cristian): amostrar N valores e testar contra a D_{Z,sigma} teorica
por chi-quadrado (binado) + conferencia de momentos (media e desvio) + cauda.
"""
import math, random
import mpmath as mp

# ---------------- distribuicao teorica ----------------
def dgauss_pmf(sigma, mu=0.0, tau=6):
    """PMF da gaussiana discreta D_{Z,sigma,mu}, truncada em +-tau*sigma."""
    lo = int(math.floor(mu - tau*sigma)); hi = int(math.ceil(mu + tau*sigma))
    w = {x: math.exp(-((x-mu)**2)/(2*sigma*sigma)) for x in range(lo, hi+1)}
    Z = sum(w.values())
    return {x: w[x]/Z for x in w}

def theo_moments(pmf):
    m = sum(x*p for x, p in pmf.items())
    v = sum((x-m)**2 * p for x, p in pmf.items())
    return m, math.sqrt(v)

# ---------------- amostradores (CDT: como os reais) ----------------
def _cdt(pmf):
    xs = sorted(pmf); cum = []; c = 0.0
    for x in xs:
        c += pmf[x]; cum.append((c, x))
    return cum

def _draw(cdt, u):
    for c, x in cdt:
        if u <= c: return x
    return cdt[-1][1]

def sampler_good(n, sigma, rng, tau=6):
    cdt = _cdt(dgauss_pmf(sigma, tau=tau))
    return [_draw(cdt, rng.random()) for _ in range(n)]

def sampler_narrow(n, sigma, rng, factor=0.90, tau=6):   # BUG: sigma pequeno demais
    cdt = _cdt(dgauss_pmf(sigma*factor, tau=tau))
    return [_draw(cdt, rng.random()) for _ in range(n)]

def sampler_truncated(n, sigma, rng, tau_bug=3):          # BUG: cauda cortada em 3*sigma
    cdt = _cdt(dgauss_pmf(sigma, tau=tau_bug))
    return [_draw(cdt, rng.random()) for _ in range(n)]

def sampler_shifted(n, sigma, rng, mu=0.25, tau=6):       # BUG: centro deslocado
    cdt = _cdt(dgauss_pmf(sigma, mu=mu, tau=tau))
    return [_draw(cdt, rng.random()) for _ in range(n)]

def sampler_lowprec(n, sigma, rng, bits=8, tau=6):        # BUG: RNG de baixa precisao (CDT grosseira)
    cdt = _cdt(dgauss_pmf(sigma, tau=tau))
    return [_draw(cdt, rng.getrandbits(bits)/(2**bits)) for _ in range(n)]

# ---------------- QA: o metodo do Projeto Prata ----------------
def _chi2_sf(x, k):
    return float(mp.gammainc(mp.mpf(k)/2, mp.mpf(x)/2, mp.inf, regularized=True))

def _bins(pmf, n, min_exp=5.0):
    """Agrupa valores em bins com contagem esperada >= min_exp (chi2 valido)."""
    xs = sorted(pmf); bins = []; cur = []; p = 0.0
    for x in xs:
        cur.append(x); p += pmf[x]
        if p*n >= min_exp:
            bins.append((set(cur), p)); cur = []; p = 0.0
    if cur:  # junta o resto no ultimo bin
        if bins:
            s, pp = bins[-1]; bins[-1] = (s | set(cur), pp + p)
        else:
            bins.append((set(cur), p))
    return bins

def certify_gaussian(samples, sigma, mu=0.0, tau=6, alpha=1e-6):
    pmf = dgauss_pmf(sigma, mu, tau)
    tmean, tstd = theo_moments(pmf)
    n = len(samples)
    lo, hi = min(pmf), max(pmf)
    out = sum(1 for s in samples if s < lo or s > hi)
    if out > max(3, 1e-4*n):   # muitas amostras fora do intervalo teorico
        return (False, 0.0, f"{out} amostras fora de [{lo},{hi}] — cauda/sigma errados.")
    bins = _bins(pmf, n)
    chi2 = 0.0
    for xset, p in bins:
        obs = sum(1 for s in samples if s in xset)
        exp = n*p
        chi2 += (obs-exp)**2/exp
    df = len(bins) - 1
    pval = _chi2_sf(chi2, df)
    emean = sum(samples)/n
    estd = math.sqrt(sum((s-emean)**2 for s in samples)/n)
    # tolerancias: erro-padrao da media ~ std/sqrt(n); do desvio ~ std/sqrt(2n)
    mean_off = abs(emean - tmean) / (tstd/math.sqrt(n))
    std_off = abs(estd - tstd) / (tstd/math.sqrt(2*n))
    ok = (pval >= alpha) and (mean_off < 6) and (std_off < 6)
    det = (f"chi2={chi2:.1f}(df={df}) p={pval:.1e} | media {emean:+.3f}(teor {tmean:+.3f}, {mean_off:.1f}sd) "
           f"| desvio {estd:.3f}(teor {tstd:.3f}, {std_off:.1f}sd)")
    return (ok, pval, det)

def _report(nome, samples, sigma):
    ok, p, det = certify_gaussian(samples, sigma)
    print(f"  {nome:<40} {'APROVADO' if ok else '*** REPROVADO (viciado) ***'}")
    print(f"       {det}")

def main():
    SIGMA = 4.0; n = 200_000
    print("="*76)
    print(f"QA DO AMOSTRADOR GAUSSIANO DISCRETO — D(Z, sigma={SIGMA})  [Falcon/FrodoKEM/BLISS]")
    print("   o metodo do Projeto Prata certificando o amostrador PQC mais delicado")
    print("="*76)
    pmf = dgauss_pmf(SIGMA); tm, ts = theo_moments(pmf)
    print(f"\n  alvo teorico: media={tm:+.3f}, desvio={ts:.3f}, cauda ate +-{int(6*SIGMA)}")
    print(f"  certificando 5 amostradores com {n} amostras cada:\n")
    r = random.Random(20260706)
    _report("1) CORRETO", sampler_good(n, SIGMA, r), SIGMA)
    _report("2) sigma pequeno demais (x0.90)", sampler_narrow(n, SIGMA, r), SIGMA)
    _report("3) cauda truncada em 3*sigma", sampler_truncated(n, SIGMA, r), SIGMA)
    _report("4) centro deslocado (mu=0.25)", sampler_shifted(n, SIGMA, r), SIGMA)
    _report("5) RNG baixa precisao (8 bits)", sampler_lowprec(n, SIGMA, r), SIGMA)
    print("\n=> O amostrador correto passa; os viciados sao REPROVADOS pelo mesmo metodo")
    print("   (teste de distribuicao) que voce criou para os primos. Construtivo, nao destrutivo.")

if __name__ == "__main__":
    main()
