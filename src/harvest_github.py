"""
HonestKeyAudit — Coletor em ESCALA de chaves SSH do GitHub (alimenta a Camada B)
================================================================================
Coleta moduli RSA de chaves SSH PUBLICAS do GitHub, em escala, de forma robusta
e RESUMIVEL, e roda batch-GCD periodicamente. O corpus serve para DOIS estudos:
  (1) batch-GCD (fatores compartilhados = chaves quebraveis) — src/batchgcd.py;
  (2) analise fundamentada na teoria (distribuicao de fase de prata / diversidade
      de gerador em chaves reais) — src/gen_anomaly.py, drift_monitor.py.

Como funciona (2 endpoints):
  - ENUMERAR usuarios: api.github.com/users?since=<id>  (precisa de token; 5000/h;
    100 usuarios por request => ~500 mil usuarios/hora).
  - PEGAR as chaves: github.com/<user>.keys  (texto cru, SEM limite de API) —
    e' o que permite escala. Concorrente e educado.

SEGURANCA: defina o token no ambiente, NAO no codigo:
    (Windows)  setx GITHUB_TOKEN "seu_token"     (feche/reabra o terminal)
    (bash)     export GITHUB_TOKEN="seu_token"

Uso:
  python src/harvest_github.py --scale 100000    # enumera+coleta ate' 100k usuarios (precisa do token)
  python src/harvest_github.py --users a b c ...  # coleta de usuarios dados (SEM token; p/ teste)
  python src/harvest_github.py --gcd              # roda batch-GCD no corpus ja' coletado

Estado (resumivel) em _harvest/:  cursor.txt (ultimo id), moduli.txt (N em hex, dedup).

AVISO HONESTO: chaves SSH do GitHub sao de DESENVOLVEDORES (OpenSSH bom) — alvo
FRACO para achar chaves quebraveis. Os achados historicos vieram de dispositivos
embarcados/IoT. Espere provavelmente ZERO no batch-GCD; o valor garantido e' o
corpus real para a analise de fingerprint (o diferencial). Alvo melhor p/ achado:
dumps de TLS de embarcados (scans.io/Rapid7) — precisa download.
"""
import os, sys, time, json, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import rsa

HDIR = os.path.join(os.path.dirname(__file__), "..", "_harvest")
os.makedirs(HDIR, exist_ok=True)
CURSOR = os.path.join(HDIR, "cursor.txt")
MODULI = os.path.join(HDIR, "moduli.txt")

def _get(url, token=None, timeout=15):
    hdr = {"User-Agent": "HonestKeyAudit", "Accept": "application/vnd.github+json"}
    if token: hdr["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=hdr)
    return urllib.request.urlopen(req, timeout=timeout)

def fetch_user_moduli(user):
    """github.com/<user>.keys -> lista de moduli RSA (int)."""
    out = []
    try:
        resp = _get(f"https://github.com/{user}.keys")
        text = resp.read().decode("utf-8", "replace")
    except Exception:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("ssh-rsa"):
            continue
        try:
            pub = load_ssh_public_key(line.encode())
            if isinstance(pub, rsa.RSAPublicKey):
                out.append(pub.public_numbers().n)
        except Exception:
            continue
    return out

def _load_seen():
    seen = set()
    if os.path.exists(MODULI):
        with open(MODULI) as f:
            for ln in f:
                ln = ln.strip()
                if ln: seen.add(int(ln, 16))
    return seen

def _append_moduli(new_Ns, seen):
    added = 0
    with open(MODULI, "a") as f:
        for N in new_Ns:
            if N not in seen:
                seen.add(N); f.write(f"{N:x}\n"); added += 1
    return added

def harvest_users(users, seen, workers=16):
    total = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for mods in ex.map(fetch_user_moduli, users):
            if mods:
                total += _append_moduli(mods, seen)
    return total

def enumerate_and_harvest(target, token):
    seen = _load_seen()
    since = int(open(CURSOR).read().strip()) if os.path.exists(CURSOR) else 0
    print(f"iniciando: {len(seen)} moduli ja' no corpus; cursor since={since}; alvo +{target} usuarios")
    users_done = 0; t0 = time.time()
    while users_done < target:
        # 1) enumerar 100 usuarios
        try:
            resp = _get(f"https://api.github.com/users?since={since}&per_page=100", token=token)
            batch = json.load(resp)
            rem = int(resp.headers.get("X-RateLimit-Remaining", "1"))
            reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                wait = max(5, int(e.headers.get("X-RateLimit-Reset", "0")) - int(time.time()))
                print(f"  rate limit; aguardando {wait}s..."); time.sleep(min(wait, 3600)); continue
            print(f"  erro enumeracao: {e}"); break
        if not batch:
            print("  fim da lista de usuarios."); break
        since = max(u["id"] for u in batch)
        open(CURSOR, "w").write(str(since))
        # 2) pegar as chaves (concorrente, sem limite de API)
        added = harvest_users([u["login"] for u in batch], seen)
        users_done += len(batch)
        total = len(seen)
        rate = users_done / max(time.time()-t0, 1e-9)
        print(f"  usuarios={users_done}  moduli_RSA={total} (+{added})  "
              f"{rate:.0f} u/s  API_rem={rem}", flush=True)
        # 3) batch-GCD periodico
        if total >= 2000 and users_done % 2000 < 100:
            _run_gcd(seen)
        if rem <= 2:
            wait = max(5, reset - int(time.time())); print(f"  API baixa; aguardando {wait}s...")
            time.sleep(min(wait, 3600))
    print(f"\nconcluido: {len(seen)} moduli RSA no corpus ({MODULI}).")
    _run_gcd(seen)

def _run_gcd(seen):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from batchgcd import find_shared_factors
    Ns = list(seen)
    if len(Ns) < 2: return
    t0 = time.time(); vulns = find_shared_factors(Ns); dt = time.time()-t0
    print(f"  [batch-GCD] {len(Ns)} moduli em {dt:.1f}s -> ", end="")
    if vulns:
        print(f"*** {len(vulns)} CHAVE(S) QUEBRAVEL(EIS)! ACHADO REAL! ***")
        for v in vulns[:10]:
            print(f"      N {v['N'].bit_length()}b tipo={v['tipo']}" +
                  (f" p={str(v['p'])[:20]}..." if v['p'] else ""))
        with open(os.path.join(HDIR, "ACHADOS.txt"), "a") as f:
            for v in vulns:
                f.write(f"{v['N']:x}\t{v['tipo']}\t{v['p'] or ''}\n")
    else:
        print("nenhum fator compartilhado (esperado; devs usam OpenSSH bom).")

def main():
    if len(sys.argv) < 2:
        print("uso: --scale <N> | --users <u1 u2 ...> | --gcd"); sys.exit(2)
    if sys.argv[1] == "--scale":
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            print("ERRO: defina GITHUB_TOKEN no ambiente (nao no codigo)."); sys.exit(1)
        enumerate_and_harvest(int(sys.argv[2]) if len(sys.argv) > 2 else 50000, token)
    elif sys.argv[1] == "--users":
        seen = _load_seen()
        added = harvest_users(sys.argv[2:], seen)
        print(f"coletados +{added} moduli RSA de {len(sys.argv)-2} usuarios; corpus={len(seen)}.")
        _run_gcd(seen)
    elif sys.argv[1] == "--gcd":
        _run_gcd(_load_seen())

if __name__ == "__main__":
    main()
