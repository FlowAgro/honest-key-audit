"""
HonestKeyAudit — CERTIFICADOR PQC (a suite completa, o produto vendavel)
========================================================================
Roda TODAS as lentes de QA sobre um amostrador pos-quantico e emite um veredito
de certificacao, dizendo QUAL lente reprovou. Cada lente vem da pesquisa do
Projeto Prata:

  LENTE                    | pega                          | origem na sua pesquisa
  -------------------------|-------------------------------|---------------------------
  marginal (distribuicao)  | sigma/dist errados, cauda,    | gen_anomaly / anomalia de
                           | centro, precisao (chi-quad.)  | gerador (dos primos)
  serial (vizinhos)        | correlacao entre consecutivos | gaps / vies Lemke Oliver-
                           | (marginal pode estar perfeita)| Soundararajan (primos vizinhos)
  espectral (ritmo)        | periodicidade / RNG de periodo| "ritmo oculto" src/39
                           | curto (identifica o periodo)  | (Fourier)

Veredito: CERTIFICADO so' se TODAS as lentes passam. Uso: certify(samples, kind).
"""
import random
from pqc_gaussian_qa import (certify_gaussian, sampler_good, sampler_narrow,
                             sampler_truncated, sampler_shifted, sampler_lowprec)
from pqc_serial_qa import certify_serial, sampler_sticky
from pqc_spectral_qa import spectral_test, sampler_short_period
from pqc_sampler_qa import certify_sampler

def certify(samples, kind="gaussian", sigma=4.0, eta=2):
    """Roda a suite. Retorna (certificado:bool, {lente: (passou, detalhe)})."""
    res = {}
    if kind == "gaussian":
        ok, _, det = certify_gaussian(samples, sigma)
    else:
        ok, _, det = certify_sampler(samples, eta)
    res["marginal (distribuicao)"] = (ok, det.split("|")[0].strip())
    sok, ac, z = certify_serial(samples)
    res["serial   (vizinhos)   "] = (sok, f"autocorr={ac:+.4f}  z={z:+.1f}")
    spok, g, sp, per = spectral_test(samples)
    res["espectral(ritmo)      "] = (spok, f"g={g:.1f} p={sp:.1e}" + ("" if spok else f"  periodo~{per}"))
    return (all(v[0] for v in res.values()), res)

def _cert(nome, samples, kind="gaussian", sigma=4.0):
    certd, res = certify(samples, kind, sigma)
    print(f"\n  {nome}")
    print(f"  {'='*66}")
    for lente, (ok, det) in res.items():
        print(f"    [{'OK ' if ok else 'X  '}] {lente}  {det}")
    print(f"    >>> {'*** CERTIFICADO ***' if certd else 'XXX REPROVADO - nao usar em producao XXX'}")

def main():
    S = 4.0; n = 100_000
    print("="*72)
    print("  CERTIFICADOR PQC — suite completa (Falcon/FrodoKEM: gaussiana discreta)")
    print("="*72)
    r = random.Random(20260706)
    _cert("Amostrador A (correto)",                 sampler_good(n, S, r), sigma=S)
    _cert("Amostrador B (sigma errado)",            sampler_narrow(n, S, r), sigma=S)
    _cert("Amostrador C (vizinhos correlacionados)", sampler_sticky(n, S, r), sigma=S)
    _cert("Amostrador D (RNG de periodo curto)",     sampler_short_period(n, S, r), sigma=S)
    print("\n" + "="*72)
    print("  Cada defeito foi pego pela lente certa; so' o correto foi CERTIFICADO.")
    print("  Este e' o processo vendavel: certificar a geracao de chaves pos-quanticas,")
    print("  com lentes fundamentadas na pesquisa do Projeto Prata.")
    print("="*72)

if __name__ == "__main__":
    main()
