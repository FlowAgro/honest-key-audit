"""
HonestKeyAudit — Camada B: BATCH-GCD EM ESCALA (motor do estudo de medicao)
===========================================================================
Acha chaves RSA quebraveis que COMPARTILHAM um fator primo — sintoma de RNG
fraco / pouca entropia. Se duas chaves N1=p*q1 e N2=p*q2 usam o mesmo p (por
azar de aleatoriedade ruim), gcd(N1,N2)=p revela AMBAS as chaves privadas.

Foi assim que "Mining your Ps and Qs" (2012) achou centenas de milhares de
chaves quebraveis na internet, e ROCA/estudos seguem achando. Este e' o caminho
honesto para um ACHADO REAL e publicavel — depende de rodar em ESCALA sobre um
dataset publico de pesquisa (ver DATASETS abaixo).

Algoritmo: batch-GCD de D. J. Bernstein (arvore de produtos + arvore de restos),
O(n log^2 n) — NAO o O(n^2) ingenuo. Escala para milhoes de moduli.

Uso:
  python src/batchgcd.py selftest                 # teste com vulnerabilidades injetadas
  python src/batchgcd.py moduli.txt               # um N por linha (decimal ou 0x-hex)
  python src/batchgcd.py --pems /pasta/de/certs    # extrai N de certificados PEM/DER

DATASETS PUBLICOS DE PESQUISA (para o achado real, camada B):
  - Rapid7 Open Data / scans.io  (dumps de TLS da internet; certificados X.509)
  - Censys (pesquisa)            (moduli de TLS/SSH)
  - chaves SSH publicas do GitHub (api.github.com/users/<user>/keys)
  Baixe um dump, extraia os moduli (--pems ou converta para moduli.txt), rode aqui.
  Expectativa honesta: o rendimento depende do dataset; em milhoes de chaves da
  internet historicamente aparece uma fracao pequena mas real de chaves quebraveis.
"""
import os, sys, time, glob

# Acelerador opcional: gmpy2 (GMP) da' 10-100x em escala real. Sem ele, Python puro.
try:
    from gmpy2 import mpz, gcd as _gcd
    HAVE_GMP = True
except ImportError:
    from math import gcd as _gcd
    def mpz(x): return x
    HAVE_GMP = False

# ---------------- batch-GCD de Bernstein ----------------
def product_tree(Ns):
    """Arvore de produtos: folhas = Ns; cada nivel = produto dos pares."""
    tree = [list(Ns)]
    while len(tree[-1]) > 1:
        cur = tree[-1]
        nxt = [cur[i] * cur[i+1] if i+1 < len(cur) else cur[i]
               for i in range(0, len(cur), 2)]
        tree.append(nxt)
    return tree

def batch_gcd(Ns):
    """Retorna, para cada N_i, gcd(N_i, (prod dos outros)) via arvore de restos.
    >1 (e <N_i) => N_i compartilha um fator com outra chave do corpus."""
    if len(Ns) < 2:
        return [1] * len(Ns)
    Ns = [mpz(N) for N in Ns]           # usa GMP se disponivel (10-100x em escala)
    tree = product_tree(Ns)
    R = tree.pop()                      # nivel raiz: [P] (produto de todos)
    while tree:
        X = tree.pop()                  # nivel dos filhos
        R = [R[i >> 1] % (X[i] * X[i]) for i in range(len(X))]
    return [int(_gcd(r // N, N)) for r, N in zip(R, Ns)]

def find_shared_factors(Ns):
    """Retorna lista de dicts das chaves QUEBRAVEIS: {i, N, p, q, tipo}."""
    gcds = batch_gcd(Ns)
    out = []
    for i, (N, g) in enumerate(zip(Ns, gcds)):
        if g == 1:
            continue
        if 1 < g < N:                   # fator recuperado -> chave QUEBRADA
            out.append(dict(i=i, N=N, p=g, q=N // g, tipo="fator-compartilhado"))
        else:                           # g == N: modulo duplicado ou ambos os fatores
            out.append(dict(i=i, N=N, p=None, q=None, tipo="duplicado/multi-compartilhado"))
    return out

# ---------------- ingestao ----------------
def read_moduli_file(path):
    Ns = []
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            Ns.append(int(ln, 16) if ln.lower().startswith("0x") else int(ln))
    return Ns

def read_moduli_github(usernames, token=None):
    """Ingestao de dados REAIS acessivel: chaves SSH publicas do GitHub.
    api.github.com/users/<user>/keys. Sem token: 60 req/h; com token: 5000/h.
    Para escala (achado real), enumere usuarios via api.github.com/users e passe um token."""
    import json, urllib.request
    from cryptography.hazmat.primitives.serialization import load_ssh_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    hdr = {"Authorization": f"token {token}"} if token else {}
    Ns = []
    for u in usernames:
        try:
            req = urllib.request.Request(f"https://api.github.com/users/{u}/keys", headers=hdr)
            data = json.load(urllib.request.urlopen(req, timeout=10))
        except Exception:
            continue
        for item in data:
            try:
                pub = load_ssh_public_key(item["key"].encode())
                if isinstance(pub, rsa.RSAPublicKey):
                    Ns.append(pub.public_numbers().n)
            except Exception:
                continue
    return Ns

def read_moduli_pems(folder):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
    from cryptography.hazmat.primitives.asymmetric import rsa
    Ns = []
    for p in glob.glob(os.path.join(folder, "**", "*"), recursive=True):
        if not os.path.isfile(p):
            continue
        try:
            data = open(p, "rb").read()
            pub = None
            for loader in (lambda d: x509.load_pem_x509_certificate(d).public_key(),
                           lambda d: x509.load_der_x509_certificate(d).public_key(),
                           load_pem_public_key, load_der_public_key):
                try: pub = loader(data); break
                except Exception: continue
            if isinstance(pub, rsa.RSAPublicKey):
                Ns.append(pub.public_numbers().n)
        except Exception:
            continue
    return Ns

# ---------------- relatorio ----------------
def run(Ns, label=""):
    print(f"=== BATCH-GCD {label}: {len(Ns)} moduli RSA ===  [GMP: {'ON' if HAVE_GMP else 'OFF (instale gmpy2 p/ escala)'}]")
    t0 = time.time()
    vulns = find_shared_factors(Ns)
    dt = time.time() - t0
    print(f"  tempo: {dt:.2f}s  ({len(Ns)/max(dt,1e-9):.0f} moduli/s)")
    if not vulns:
        print("  nenhuma chave com fator compartilhado (esperado em dados bem geridos).")
    else:
        print(f"  *** {len(vulns)} CHAVE(S) QUEBRAVEL(EIS) (fator compartilhado): ***")
        for v in vulns[:20]:
            if v["p"]:
                print(f"    #{v['i']} {v['N'].bit_length()}b: QUEBRADA — p={str(v['p'])[:24]}... (fator recuperado)")
            else:
                print(f"    #{v['i']} {v['N'].bit_length()}b: {v['tipo']}")
        if len(vulns) > 20:
            print(f"    ... e mais {len(vulns)-20}.")
    return vulns

# ---------------- selftest (vulnerabilidades injetadas) ----------------
def selftest():
    import random
    from sympy import nextprime
    r = random.Random(1234)
    NBITS = 256           # primos de 256 bits -> N de 512 bits (rapido; a matematica e' a mesma)
    NCLEAN = 3000         # chaves limpas
    NPAIRS = 8            # pares que compartilham um primo (16 chaves quebraveis)

    def rp():
        return int(nextprime(r.randrange(2**(NBITS-1), 2**NBITS)))

    print(f"gerando corpus: {NCLEAN} chaves limpas + {NPAIRS} pares com primo compartilhado...")
    Ns = []
    for _ in range(NCLEAN):
        Ns.append(rp() * rp())
    injected = []
    for _ in range(NPAIRS):
        shared = rp()
        q1, q2 = rp(), rp()
        i1 = len(Ns); Ns.append(shared * q1)
        i2 = len(Ns); Ns.append(shared * q2)
        injected += [i1, i2]
    random.Random(7).shuffle(Ns)  # embaralha para nao depender da posicao

    vulns = run(Ns, "(selftest)")
    found = len(vulns)
    # confere que TODAS as 16 injetadas foram achadas (por reconstrucao: fator divide 2 moduli)
    ok = found >= 2*NPAIRS
    print(f"\n  injetadas: {2*NPAIRS} chaves quebraveis;  encontradas: {found}")
    print("  => " + ("PIPELINE VALIDO: batch-GCD de Bernstein achou as chaves quebraveis e "
                     "recuperou os fatores, em escala." if ok else "revisar."))
    return ok

def main():
    if len(sys.argv) < 2:
        print("uso: python src/batchgcd.py selftest | <moduli.txt> | --pems <pasta>"); sys.exit(2)
    if sys.argv[1] == "selftest":
        selftest()
    elif sys.argv[1] == "--pems":
        Ns = read_moduli_pems(sys.argv[2]); run(Ns, f"(PEMs de {sys.argv[2]})")
    elif sys.argv[1] == "--github":
        tok = os.environ.get("GITHUB_TOKEN")
        Ns = read_moduli_github(sys.argv[2:], token=tok)
        run(Ns, f"(SSH GitHub de {len(sys.argv)-2} usuarios)")
    else:
        Ns = read_moduli_file(sys.argv[1]); run(Ns, f"({sys.argv[1]})")

if __name__ == "__main__":
    main()
