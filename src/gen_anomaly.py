"""
HonestKeyAudit — Auditor de ANOMALIA DE GERADOR (o diferencial, multi-lente)
=============================================================================
Os auditores do mercado checam CADA chave contra classes fracas CONHECIDAS
(ROCA, Fermat, batch-GCD). Este modulo faz algo diferente e pouco empacotado:
testa se uma POPULACAO de chaves e' estatisticamente consistente com geracao
aleatoria correta — detectando um VIES no GERADOR que passa despercebido na
auditoria por-chave, mas que pode virar o proximo ROCA.

DUAS LENTES (cada uma pega vieses diferentes; ambas computaveis so' do N publico):
  (A) UNIFORMIDADE DE RESIDUO  — chi-quadrado de N mod m para primos pequenos.
      Pega vies modular do RNG (ex.: p mod 3 enviesado).
  (B) FASE DE PRATA / HECKE     — KS da equidistribuicao de phi(N)=frac(log_delta N)
      contra uniforme [0,1). E' o objeto central do Projeto Prata (paper da Barreira):
      um gerador honesto tem phi(N) equidistribuido (teorema de Hecke, medido em
      LENTE_PRATA.md); um vies no EIXO LOGARITMICO (ex.: primos de faixa estreita =
      baixa entropia de tamanho) desvia AQUI, e a lente (A) nao ve.

⚠️ CALIBRACAO (achado do experimento de proveniencia, src/provenance.py):
  A fase de prata phi(N) de chaves do OpenSSL NAO e' equidistribuida — o OpenSSL
  forca os 2 bits altos de cada primo, comprimindo a faixa de N (D=0.28, p=1e-10).
  Logo testar phi(N) contra o UNIFORME PURO da' FALSO-POSITIVO em chaves OpenSSL
  legitimas. O uso correto e' RELATIVO: comparar contra uma BASELINE de chaves
  confiaveis do MESMO gerador (deteccao de DRIFT), nao contra a teoria. Este e'
  o formato certo de produto (monitoramento continuo). A funcao de uniformidade
  abaixo serve para (a) proveniencia/fingerprint e (b) baseline; NAO usar o
  p-valor vs uniforme como alarme absoluto num gerador com restricoes conhecidas.

Este e' o diferencial fundamentado na NOSSA pesquisa publicada, nao numa
estatistica generica. E' anomalia/QA (alerta precoce), nao prova de quebra.

Uso:  python src/gen_anomaly.py selftest
API:  audit_generator(list_of_N) -> relatorio das duas lentes + veredito
"""
import mpmath as mp
from sympy import isprime

SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
_DPS = 60

# ---------------- lente (A): uniformidade de residuo (chi-quadrado) ----------------
def _chi2_sf(x, k):
    return float(mp.gammainc(mp.mpf(k)/2, mp.mpf(x)/2, mp.inf, regularized=True))

def residue_uniformity(Ns, m):
    counts = [0]*m
    for N in Ns:
        counts[N % m] += 1
    obs = counts[1:] if isprime(m) else counts
    total = sum(obs); k = len(obs)
    if total == 0 or k < 2:
        return (0.0, 1.0, k-1)
    exp = total / k
    chi2 = sum((o - exp)**2 / exp for o in obs)
    return (chi2, _chi2_sf(chi2, k-1), k-1)

# ---------------- lente (B): fase de prata / Hecke (KS vs uniforme) ----------------
def silver_phase(N):
    """phi(N) = frac(log_delta N), delta = 1+sqrt(2). O objeto do paper da Barreira."""
    mp.mp.dps = _DPS
    delta = 1 + mp.sqrt(2)
    lam = mp.log(N) / mp.log(delta)
    return float(lam - mp.floor(lam))

def _ks_p(D, n):
    """p-valor KS assintotico com correcao de Stephens (pequenas amostras)."""
    x = (mp.sqrt(n) + 0.12 + 0.11/mp.sqrt(n)) * D
    s = mp.mpf(0)
    for k in range(1, 101):
        s += (-1)**(k-1) * mp.e**(-2*k*k*x*x)
    return float(min(max(2*s, mp.mpf(0)), mp.mpf(1)))

def silver_phase_uniformity(Ns):
    """KS da equidistribuicao de phi(N). Retorna (D, p)."""
    us = sorted(silver_phase(N) for N in Ns)
    n = len(us)
    if n < 5:
        return (0.0, 1.0)
    D = 0.0
    for i, u in enumerate(us):
        D = max(D, (i+1)/n - u, u - i/n)
    return (D, _ks_p(D, n))

# ---------------- bateria + veredito ----------------
def audit_generator(Ns, alpha=0.01):
    tests = []
    for m in SMALL_PRIMES:
        chi2, p, df = residue_uniformity(Ns, m)
        tests.append(dict(lente="residuo", nome=f"N mod {m}", stat=chi2, p=p))
    D, p_sp = silver_phase_uniformity(Ns)
    tests.append(dict(lente="fase-prata", nome="phi(N) Hecke (KS)", stat=D, p=p_sp))

    minp = min(t["p"] for t in tests)
    thr = alpha / len(tests)  # Bonferroni
    return dict(n=len(Ns), tests=tests, min_p=minp, threshold=thr, anomalous=minp < thr)

def _report(title, rep):
    print(f"\n--- {title}  (n={rep['n']}) ---")
    for t in sorted(rep["tests"], key=lambda t: t["p"])[:4]:
        flag = "  <== DESVIO" if t["p"] < rep["threshold"] else ""
        print(f"    [{t['lente']:>10}] {t['nome']:<18} stat={t['stat']:8.2f}  p={t['p']:.2e}{flag}")
    verd = "ANOMALO (gerador com vies)" if rep["anomalous"] else "consistente com aleatorio"
    print(f"    veredito: {verd}   (min p={rep['min_p']:.2e} vs Bonferroni {rep['threshold']:.2e})")

def selftest():
    import random
    from sympy import nextprime
    from roca import det_roca
    r = random.Random(20260706); HALF = 128; NK = 300

    def rp():
        return int(nextprime(r.randrange(2**(HALF-1), 2**HALF)))

    def rp_residuo():  # vies modular: p mod 3 enviesado (lente A deve pegar)
        while True:
            p = int(nextprime(r.randrange(2**(HALF-1), 2**HALF)))
            if p % 3 == 1 or r.random() < 0.15:
                return p

    def rp_tamanho():  # vies de tamanho: primos de faixa ESTREITA (lente B deve pegar)
        base = 2**(HALF-1) + 2**(HALF-1)//2
        return int(nextprime(base + r.randrange(0, 2**(HALF-40))))  # janela ~2^88, bem estreita

    good = [rp()*rp() for _ in range(NK)]
    bias_res = [rp_residuo()*rp_residuo() for _ in range(NK)]
    bias_tam = [rp_tamanho()*rp_tamanho() for _ in range(NK)]

    print("="*72)
    print("AUDITOR DE ANOMALIA DE GERADOR — multi-lente (residuo + fase de prata/Hecke)")
    print("="*72)

    # por-chave (ROCA) nao ve' nenhum dos dois vieses
    rb = sum(1 for N in bias_res if det_roca(N)[0])
    rt = sum(1 for N in bias_tam if det_roca(N)[0])
    print(f"\n[auditoria POR-CHAVE, estilo mercado] ROCA marca: {rb}/{NK} (vies residuo), "
          f"{rt}/{NK} (vies tamanho) — AMBOS passam despercebidos por-chave.")

    rg = audit_generator(good); rr = audit_generator(bias_res); rtm = audit_generator(bias_tam)
    _report("GERADOR BOM", rg)
    _report("GERADOR com VIES MODULAR (p mod 3)  -> esperado: lente RESIDUO pega", rr)
    _report("GERADOR com VIES DE TAMANHO (faixa estreita) -> esperado: lente FASE-PRATA pega", rtm)

    # veredito do teste: bom passa; cada vies e' pego pela lente certa
    res_caught = any(t["lente"] == "residuo" and t["p"] < rr["threshold"] for t in rr["tests"])
    tam_caught = any(t["lente"] == "fase-prata" and t["p"] < rtm["threshold"] for t in rtm["tests"])
    ok = (not rg["anomalous"]) and res_caught and tam_caught and rb == 0 and rt == 0
    print("\n=> " + ("MULTI-LENTE VALIDO: cada lente pega um vies diferente que a checagem por-chave "
                     "deixa passar. A lente FASE-PRATA e' o nosso diferencial (fundada no paper da Barreira)."
                     if ok else "revisar (alguma lente nao pegou o vies esperado)."))
    return ok

if __name__ == "__main__":
    selftest()
