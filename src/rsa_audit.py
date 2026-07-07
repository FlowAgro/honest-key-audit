"""
Projeto Prata — Auditor de chaves RSA (trilha b, defensiva)
============================================================
Consolida o src/04 (fingerprints, AUC=1.00) numa FERRAMENTA REAL de auditoria.
"Super dispositivo honesto": DESCobre chaves fracas (modo audit) E EVITA
vulnerabilidades (modo guard, na geração). Tudo a partir do N público.

HONESTIDADE DE ESCOPO (importante):
  Estes detectores acham classes fracas CONHECIDAS — primos próximos (Fermat),
  fator compartilhado entre chaves (batch-GCD), viés de classe mod-M (ROCA),
  suavidade de p-1 (Pollard p-1). Eles NÃO quebram RSA forte com primos
  honestamente aleatórios. O valor defensivo é duplo:
    - audit: encontrar chaves já emitidas que caíram numa classe fraca;
    - guard: garantir que uma chave recém-gerada NÃO cai em nenhuma classe fraca.

Detecções (cada uma: vulnerável? score 0..1 detalhe):
  1. FERMAT     — |p-q| pequeno: fatoração de Fermat em poucos passos.
  2. BATCH-GCD  — fator compartilhado com outra chave do corpus (PRNG ruim/reação).
  3. MOD-M      — viés estilo ROCA: N ≡ 1 (mod m) para vários m pequenos.
  4. P-1 SMOOTH — (modo guard, tem p) p-1 B-liso => vulnerável a Pollard p-1.

Uso (CLI):
  python src/56_key_audit_tool.py selftest
  python src/56_key_audit_tool.py audit  arquivo_Ns.txt
  python src/56_key_audit_tool.py guard   <p> <q>
  (Ns: um por linha, decimal ou 0x...; p,q: decimal ou 0x...)

Saída: relatório por chave com a vulnerabilidade encontrada (se houver).
"""
import os, sys, math, random, argparse
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from functools import reduce
from sympy import nextprime, isprime, gcd as sgcd

OUTDIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(OUTDIR, exist_ok=True)

# ============================================================ detectores
SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23]
M = reduce(lambda a, b: a*b, SMALL_PRIMES)
_FERMAT_STEPS = 2000          # passos de Fermat; se acha aqui, é fraca
_P1_SMOOTH_B = 1_000_000      # bound p/ suavidade de p-1 (Pollard p-1)

def _is_square(n):
    if n < 0: return False
    r = math.isqrt(n); return r*r == n

def det_fermat(N, T=_FERMAT_STEPS):
    """Fatoração de Fermat: a²-N quadrado perfeito. Acha se |p-q| pequeno.
    Retorna (vulnerável, score, detalhe)."""
    if N < 2: return (False, 0.0, "N<2")
    a = math.isqrt(N)
    if a*a < N: a += 1
    for k in range(T):
        b2 = a*a - N
        if _is_square(b2):
            b = math.isqrt(b2)
            p, q = a-b, a+b
            return (True, 1.0/(k+1), f"Fermat: fatorado em {k+1} passos (|p-q| pequeno). p={p}")
        a += 1
    return (False, 0.0, f"resistente a Fermat ({T} passos).")

def det_modM(N):
    """Viés ROCA: N ≡ 1 (mod m) para m em SMALL_PRIMES => p,q numa classe restrita."""
    hits = sum(1 for m in SMALL_PRIMES if N % m == 1)
    score = hits / len(SMALL_PRIMES)
    vuln = score >= 0.875   # 7/8 ou 8/8: viés de classe forte; limpo raramente passa de ~1/8
    return (vuln, score,
            f"mod-M: {hits}/{len(SMALL_PRIMES)} primos com N≡1 (classe restrita estilo ROCA)." if vuln
            else f"mod-M: {hits}/{len(SMALL_PRIMES)} (sem viés de classe).")

def det_batch_gcd(Ns):
    """Para cada N_i, gcd(N_i, prod_{j≠i} N_j) > 1 => fator compartilhado.
    Retorna lista de (vulnerável, score, detalhe) paralela a Ns."""
    if not Ns:
        return []
    prod = reduce(lambda a, b: a*b, Ns)
    out = []
    for N in Ns:
        g = int(sgcd(N, prod // N))
        if g > 1:
            out.append((True, 1.0, f"batch-GCD: fator compartilhado com outra chave do corpus (g>1)."))
        else:
            out.append((False, 0.0, "batch-GCD: sem fator compartilhado no corpus."))
    return out

def det_p1_smooth(p, B=_P1_SMOOTH_B):
    """(modo guard) p-1 B-liso => vulnerável a Pollard p-1. Trial division até B."""
    if p < 2: return (False, 0.0, "p<2")
    n = p - 1
    largest = 1
    for pr in range(2, B+1):
        if pr*pr > n and n > 1:
            largest = max(largest, n); n = 1; break
        while n % pr == 0:
            largest = max(largest, pr); n //= pr
        if n == 1: break
    if n == 1:
        return (True, 1.0, f"p-1 é B-liso (B={B}): maior fator={largest} ≤ B => Pollard p-1 fatora.")
    return (False, 0.0, f"p-1 NÃO é B-liso (B={B}): resto {n} (tem fator > B) => resistente a Pollard p-1.")

# ============================================================ orquestração
def audit(Ns, verbose=False):
    """Modo AUDIT: dado um corpus de N públicos, encontra chaves fracas.
    Retorna lista de dicionários (uma por chave) com detecções."""
    bg = det_batch_gcd(Ns)
    reports = []
    for i, N in enumerate(Ns):
        ferm = det_fermat(N)
        modm = det_modM(N)
        vulns = []
        if ferm[0]: vulns.append(("FERMAT", ferm))
        if modm[0]: vulns.append(("MOD-M", modm))
        if bg[i][0]: vulns.append(("BATCH-GCD", bg[i]))
        reports.append(dict(index=i, N=N, vulnerable=len(vulns)>0, vulns=vulns,
                            fermat=ferm, modM=modm, batch_gcd=bg[i]))
    return reports

def guard(p, q):
    """Modo GUARD: dado (p,q) recém-gerados, garante que NÃO caem em classe fraca.
    Retorna (aprovado, lista_de_problemas)."""
    problems = []
    if p == q: problems.append(("IGUAIS", "p == q (chave degenerada)."))
    N = p*q
    ferm = det_fermat(N)
    if ferm[0]: problems.append(("FERMAT", ferm[2]))
    modm = det_modM(N)
    if modm[0]: problems.append(("MOD-M", modm[2]))
    sm = det_p1_smooth(p)
    if sm[0]: problems.append(("P-1(p)", sm[2]))
    sm2 = det_p1_smooth(q)
    if sm2[0]: problems.append(("P-1(q)", sm2[2]))
    return (len(problems)==0, problems)

# ============================================================ autoteste (reproduz AUC=1.00)
def _auc(scores, labels):
    pos = [s for s,l in zip(scores,labels) if l==1]; neg=[s for s,l in zip(scores,labels) if l==0]
    if not pos or not neg: return float('nan')
    w=sum(1.0 if sp>sn else (0.5 if sp==sn else 0.0) for sp in pos for sn in neg)
    return w/(len(pos)*len(neg))

def selftest(bits=256, n=60, seed=31415926):
    r = random.Random(seed); HALF=bits//2
    def rp(): return int(nextprime(r.randrange(2**(HALF-1),2**HALF)))
    clean=[rp()*rp() for _ in range(n)]
    # fracas: Fermat (p,q próximos)
    ferm=[]
    for _ in range(n):
        p=rp(); q=int(nextprime(p+r.randrange(2,2**20))); ferm.append(p*q)
    sc=[det_fermat(N)[1] for N in clean]+[det_fermat(N)[1] for N in ferm]
    lb=[0]*n+[1]*n
    a_ferm=_auc(sc,lb); fp_ferm=sum(1 for s in sc[:n] if s>0)
    # fracas: ROCA (p,q ≡ 1 mod M)
    def rocaN():
        while True:
            t=r.randrange(2**(HALF-1)//M,2**HALF//M); c=t*M+1
            if isprime(c): return c
    roca=[rocaN()*rocaN() for _ in range(n)]
    clean3=[rp()*rp() for _ in range(n)]
    sc3=[det_modM(N)[1] for N in clean3]+[det_modM(N)[1] for N in roca]
    a_mod=_auc(sc3,[0]*n+[1]*n); fp_mod=sum(1 for N in clean3 if det_modM(N)[0])
    # fracas: batch-GCD (primo compartilhado)
    shared=rp(); sh=[shared*rp() for _ in range(n)]
    cl2=[rp()*rp() for _ in range(n)]
    bg=det_batch_gcd(sh+cl2)
    a_gcd=_auc([1.0 if v else 0.0 for v,_ in [(b[0],b) for b in bg]],[1]*n+[0]*n)
    fp_gcd=sum(1 for b in bg[n:] if b[0])  # falso-positivo = clean marcado
    lines=[]
    lines.append("="*70); lines.append(f"AUTOTESTE do auditor — {bits}-bit, {n} chaves/classe"); lines.append("="*70)
    lines.append(f"  FERMAT  (|p-q| pequeno):    AUC={a_ferm:.4f}  FP em limpas={fp_ferm}")
    lines.append(f"  MOD-M   (classe ROCA):       AUC={a_mod:.4f}  FP em limpas={fp_mod}")
    lines.append(f"  BATCH-GCD (fator compart.):  AUC={a_gcd:.4f}  FP em limpas={fp_gcd}")
    ok = (a_ferm>0.99 and a_mod>0.99 and a_gcd>0.99 and fp_ferm==0 and fp_mod==0 and fp_gcd==0)
    lines.append("  => "+"FERRAMENTA VÁLIDA (AUC=1.00, zero FP)" if ok else "ALERTA: revisar detectores.")
    return "\n".join(lines), ok

# ============================================================ CLI
def _parse_int(s):
    s=s.strip()
    return int(s,16) if s.lower().startswith("0x") else int(s)

def main():
    ap=argparse.ArgumentParser(description="Auditor de chaves RSA (descobre e evita vulnerabilidades estruturais).")
    sub=ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="autoteste (reproduz AUC=1.00 em chaves sintéticas)")
    a=sub.add_parser("audit", help="audita um corpus de N públicos (um por linha, decimal ou 0x...)")
    a.add_argument("file")
    g=sub.add_parser("guard", help="verifica se (p,q) recém-gerados caem em classe fraca")
    g.add_argument("p"); g.add_argument("q")
    g.add_argument("--out", help="salvar relatório em results/")
    args=ap.parse_args()

    if args.cmd=="selftest":
        txt,ok=selftest()
        print(txt)
    elif args.cmd=="audit":
        with open(args.file) as f:
            Ns=[_parse_int(l) for l in f if l.strip() and not l.strip().startswith("#")]
        reps=audit(Ns)
        print(f"=== AUDIT: {len(Ns)} chaves ===")
        nvuln=0
        for rp in reps:
            if rp["vulnerable"]:
                nvuln+=1
                names=[v[0] for v in rp["vulns"]]
                print(f"  [#{rp['index']}] VULNERÁVEL: {', '.join(names)}")
                for name,d in rp["vulns"]:
                    print(f"        {name}: {d[2]}")
            else:
                print(f"  [#{rp['index']}] ok")
        print(f"=== {nvuln}/{len(Ns)} chaves vulneráveis ===")
    elif args.cmd=="guard":
        p=_parse_int(args.p); q=_parse_int(args.q)
        aprovado,probs=guard(p,q)
        print(f"=== GUARD: N={p*q} ===")
        if aprovado:
            print("  APROVADA: não cai em nenhuma classe fraca conhecida (Fermat, mod-M, p-1 liso).")
        else:
            print("  REPROVADA: cai em classe fraca — NÃO usar.")
            for name,desc in probs:
                print(f"    {name}: {desc}")
    if getattr(args,"out",None):
        with open(os.path.join(OUTDIR,args.out),"w",encoding="utf-8") as f:
            f.write("relatório guard\n")

if __name__=="__main__":
    main()
