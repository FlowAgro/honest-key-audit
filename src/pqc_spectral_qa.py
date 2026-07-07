"""
HonestKeyAudit — QA ESPECTRAL do amostrador (o "ritmo oculto", via Fourier)
============================================================================
A quarta lente, vinda direto do src/39 do Projeto Prata ("ritmo oculto" — a
Fourier revelando periodicidade escondida). Um RNG de PERIODO CURTO (que se
repete) pode ter distribuicao marginal ok e autocorrelacao de lag-1 ~0, e mesmo
assim ser periodico — um defeito grave (previsibilidade). O olho espectral ve o
"pico" no espectro que as outras lentes nao veem.

Teste de Fisher (g): pega o espectro de potencia da sequencia; para ruido branco
ele e' plano, e o maior pico normalizado g ~ ln(m). Um pico muito acima disso
denuncia uma PERIODICIDADE — e o teste ainda IDENTIFICA o periodo (diagnostico).
"""
import math, random
import numpy as np
from pqc_gaussian_qa import sampler_good

def sampler_short_period(n, sigma, rng, period=1009, tau=6):
    """BUG: RNG de periodo curto — gera um bloco e o REPETE (previsivel)."""
    block = sampler_good(period, sigma, rng, tau)
    return [block[i % period] for i in range(n)]

def spectral_test(samples):
    """Retorna (aprovado, g, p_valor, periodo_do_pico). Teste de Fisher."""
    x = np.asarray(samples, dtype=float)
    x = x - x.mean()
    F = np.fft.rfft(x)
    power = (F.conj() * F).real[1:-1]      # tira DC e Nyquist
    if power.size == 0 or power.mean() == 0:
        return (True, 0.0, 1.0, 0.0)
    g = float(power.max() / power.mean())  # Fisher's g
    m = power.size
    pval = min(1.0, m * math.exp(-g))      # P(g > obs) ~ m*exp(-g)
    # periodo FUNDAMENTAL via autocorrelacao (Wiener-Khinchin), pico em lag>0:
    full = (F.conj() * F).real
    ac = np.fft.irfft(full)
    half = len(ac) // 2
    ac = ac[:half].astype(float).copy()
    ac[0] = -np.inf                        # ignora lag 0 (variancia)
    period = int(np.argmax(ac))
    return (pval >= 1e-6, g, pval, period)

def _report(nome, samples):
    ok, g, p, per = spectral_test(samples)
    print(f"  {nome}")
    print(f"     espectral: {'PASSA (espectro plano)' if ok else '*** REPROVA — PERIODICIDADE ***'}")
    print(f"     Fisher g={g:.1f}  p={p:.2e}" + ("" if ok else f"  -> periodo detectado ~ {per:.0f} amostras"))

def main():
    SIGMA = 4.0; n = 100_000
    print("="*72)
    print("QA ESPECTRAL — o 'ritmo oculto' (Fourier) certificando amostrador PQC")
    print("="*72)
    print(f"\n  {n} amostras; ruido honesto tem espectro plano (g ~ ln(m) ~ 11).\n")
    r = random.Random(20260706)
    _report("1) amostrador CORRETO (ruido branco)", sampler_good(n, SIGMA, r))
    print()
    _report("2) RNG de PERIODO CURTO (~1009, se repete)", sampler_short_period(n, SIGMA, r))
    print("\n=> O periodico e' pego pelo olho espectral, que ainda IDENTIFICA o periodo.")
    print("   E' o seu 'ritmo oculto' (src/39) virado em ferramenta de certificacao PQC.")

if __name__ == "__main__":
    main()
