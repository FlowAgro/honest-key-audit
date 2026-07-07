"""
HonestKeyAudit — QA de AMOSTRADOR pos-quantico (o metodo do Projeto Prata, no futuro)
=====================================================================================
Aplicacao CONSTRUTIVA (nao destrutiva) do metodo do Projeto Prata as chaves do
futuro. A criptografia pos-quantica (ML-KEM/Kyber, ML-DSA/Dilithium) e' baseada
em RETICULADOS (geometria), e a seguranca depende da QUALIDADE de uma AMOSTRAGEM:
o "ruido" que forma a chave precisa seguir uma distribuicao exata. Se o amostrador
tem vies (RNG fraco, bug, bit preso), a seguranca degrada SILENCIOSAMENTE.

Este e' o mesmo METODO que voce desenvolveu (geometrizar a saida de um gerador e
testar a distribuicao — citoesqueleto, discrepancia de Hecke, gen_anomaly), agora
CERTIFICANDO um amostrador pos-quantico. Nao quebra nada; CERTIFICA. E' um PROCESSO
vendavel: "certificamos que a sua geracao de chaves pos-quanticas amostra correto."

Alvo: a Distribuicao Binomial Centrada (CBD) do Kyber/ML-KEM (eta=2), a distribuicao
REAL usada no padrao NIST. Amostra 2*eta bits; saida = (soma dos primeiros eta) -
(soma dos ultimos eta). Distribuicao teorica (eta=2, moeda justa):
   -2: 1/16   -1: 4/16   0: 6/16   +1: 4/16   +2: 1/16
"""
import random
from math import comb
import mpmath as mp

ETA = 2
# distribuicao teorica CBD(eta) com bits justos: P(d) = sum_k C(eta,k)C(eta,k+d) / 2^(2eta)
def cbd_theoretical(eta=ETA):
    dist = {}
    denom = 2**(2*eta)
    for d in range(-eta, eta+1):
        s = sum(comb(eta, k) * comb(eta, k+d) for k in range(0, eta+1) if 0 <= k+d <= eta)
        dist[d] = s / denom
    return dist

# ---------------- amostradores ----------------
def sampler_good(n, rng, eta=ETA):
    """Amostrador CORRETO: bits justos, CBD do Kyber."""
    out = []
    for _ in range(n):
        bits = [rng.getrandbits(1) for _ in range(2*eta)]
        out.append(sum(bits[:eta]) - sum(bits[eta:]))
    return out

def sampler_biased_rng(n, rng, eta=ETA, p1=0.62):
    """BUG realista: RNG viciado (bits com P(1)=p1 != 0.5) — entropia ruim."""
    out = []
    for _ in range(n):
        bits = [1 if rng.random() < p1 else 0 for _ in range(2*eta)]
        out.append(sum(bits[:eta]) - sum(bits[eta:]))
    return out

def sampler_uniform_bug(n, rng, eta=ETA):
    """BUG realista: implementou UNIFORME em vez da binomial (distribuicao errada)."""
    return [rng.randint(-eta, eta) for _ in range(n)]

def sampler_stuck_bit(n, rng, eta=ETA):
    """BUG realista: um bit PRESO em 0 (falha de hardware/RNG)."""
    out = []
    for _ in range(n):
        bits = [rng.getrandbits(1) for _ in range(2*eta)]
        bits[0] = 0  # bit preso
        out.append(sum(bits[:eta]) - sum(bits[eta:]))
    return out

# ---------------- QA: o metodo do Projeto Prata (teste de distribuicao) ----------------
def _chi2_sf(x, k):
    return float(mp.gammainc(mp.mpf(k)/2, mp.mpf(x)/2, mp.inf, regularized=True))

def certify_sampler(samples, eta=ETA, alpha=1e-6):
    """Certifica um amostrador: a saida bate com a CBD teorica? (chi-quadrado).
    Retorna (aprovado, p_valor, detalhe)."""
    theo = cbd_theoretical(eta)
    n = len(samples)
    obs = {d: 0 for d in theo}
    out_of_range = 0
    for s in samples:
        if s in obs: obs[s] += 1
        else: out_of_range += 1
    if out_of_range:
        return (False, 0.0, f"{out_of_range} amostras FORA do intervalo valido [-{eta},{eta}] — bug grave.")
    chi2 = sum((obs[d] - n*theo[d])**2 / (n*theo[d]) for d in theo)
    df = len(theo) - 1
    p = _chi2_sf(chi2, df)
    aprovado = p >= alpha
    return (aprovado, p, f"chi2={chi2:.1f} (df={df}), p={p:.2e}")

def _report(nome, samples):
    ap, p, det = certify_sampler(samples)
    tag = "APROVADO (amostra correto)" if ap else "*** REPROVADO (amostrador viciado) ***"
    print(f"  {nome:<34} {tag}")
    print(f"       {det}")

def main():
    n = 100_000
    print("="*72)
    print("QA DE AMOSTRADOR POS-QUANTICO — CBD do Kyber/ML-KEM (eta=2)")
    print("   o metodo do Projeto Prata (testar a distribuicao do gerador) no futuro")
    print("="*72)
    theo = cbd_theoretical()
    print(f"\n  distribuicao teorica (padrao NIST): " +
          "  ".join(f"{d:+d}:{theo[d]:.4f}" for d in sorted(theo)))
    print(f"  certificando 4 amostradores com {n} amostras cada:\n")
    r = random.Random(20260706)
    _report("1) amostrador CORRETO", sampler_good(n, r))
    _report("2) RNG viciado (P(bit=1)=0.62)", sampler_biased_rng(n, r))
    _report("3) distribuicao errada (uniforme)", sampler_uniform_bug(n, r))
    _report("4) bit preso em 0 (hardware)", sampler_stuck_bit(n, r))
    print("\n=> O amostrador correto passa; os TRES viciados sao REPROVADOS.")
    print("   Mesmo metodo do gen_anomaly (testar a distribuicao do gerador), agora")
    print("   CERTIFICANDO a geracao de chaves pos-quanticas. Construtivo, nao destrutivo.")

if __name__ == "__main__":
    main()
