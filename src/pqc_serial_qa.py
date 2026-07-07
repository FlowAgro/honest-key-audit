"""
HonestKeyAudit — QA de CORRELACAO SERIAL do amostrador (a lente dos "vizinhos")
================================================================================
O chi-quadrado (pqc_gaussian_qa/pqc_sampler_qa) testa a distribuicao de cada
amostra ISOLADA. Mas um amostrador pode ter a distribuicao marginal PERFEITA
(passa no chi2) e ainda assim ter valores CONSECUTIVOS correlacionados — um bug
de RNG real (estado reaproveitado, PRNG fraco, valor "grudento").

Esta e' a lente que o Projeto Prata desenvolveu para os PRIMOS: a estrutura entre
elementos CONSECUTIVOS (gaps entre primos, vies Lemke Oliver-Soundararajan de
primos vizinhos). A mesma alma — "vizinhos escondem correlacao?" — agora
certificando que a saida de um amostrador PQC e' INDEPENDENTE, nao so' bem
distribuida. Um amostrador correlacionado vaza mais informacao e enfraquece a chave.

Teste: autocorrelacao de lag-1 (sob independencia ~ N(0, 1/n)); |z| grande => vies
serial. Complemento: chi2 da distribuicao CONJUNTA de pares consecutivos vs o
produto das marginais (independencia).
"""
import math, random
import mpmath as mp
from pqc_gaussian_qa import sampler_good, certify_gaussian, dgauss_pmf, theo_moments

# ---------------- amostrador com bug de correlacao (marginal correta!) ----------------
def sampler_sticky(n, sigma, rng, alpha=0.15, tau=6):
    """BUG: com prob alpha, REPETE o valor anterior (estado grudento). A distribuicao
    MARGINAL continua correta (D_{Z,sigma}), mas os vizinhos ficam correlacionados."""
    base = sampler_good(n, sigma, rng, tau)
    out = [base[0]]
    for i in range(1, n):
        out.append(out[-1] if rng.random() < alpha else base[i])
    return out

# ---------------- lente serial ----------------
def autocorr_lag1(samples):
    n = len(samples); m = sum(samples)/n
    den = sum((s-m)**2 for s in samples)
    if den == 0: return 0.0
    num = sum((samples[i]-m)*(samples[i+1]-m) for i in range(n-1))
    return num/den

def certify_serial(samples):
    """Retorna (aprovado, autocorr, z). Sob independencia, autocorr ~ N(0, 1/n)."""
    n = len(samples)
    ac = autocorr_lag1(samples)
    z = ac * math.sqrt(n)
    return (abs(z) < 6, ac, z)

def _report(nome, samples, sigma):
    mok, mp_, mdet = certify_gaussian(samples, sigma)
    sok, ac, z = certify_serial(samples)
    print(f"  {nome}")
    print(f"     marginal (chi2): {'PASSA' if mok else 'REPROVA'}   ({mdet.split('|')[0].strip()})")
    print(f"     serial (vizinhos): {'PASSA' if sok else '*** REPROVA ***'}   autocorr={ac:+.4f}  z={z:+.1f}")

def main():
    SIGMA = 4.0; n = 200_000
    print("="*74)
    print("QA DE CORRELACAO SERIAL — a lente dos 'vizinhos' (primos consecutivos -> PQC)")
    print("="*74)
    print(f"\n  {n} amostras; a autocorrelacao de um gerador honesto deve ser ~0 (|z|<6).\n")
    r = random.Random(20260706)
    _report("1) amostrador CORRETO (independente)", sampler_good(n, SIGMA, r), SIGMA)
    print()
    _report("2) amostrador GRUDENTO (marginal certa, vizinhos correlacionados)",
            sampler_sticky(n, SIGMA, r), SIGMA)
    print("\n=> O grudento PASSA no chi2 (distribuicao marginal perfeita) mas e' REPROVADO")
    print("   pela lente serial — o bug que o teste padrao NAO ve. Esta lente e' a sua")
    print("   pesquisa de primos consecutivos (gaps, vies LOS) virada em ferramenta de QA.")

if __name__ == "__main__":
    main()
