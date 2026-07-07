"""
PQCQ — Post-Quantum sampler Certification (the flagship CLI)
===========================================================
Certifies the OUTPUT of a post-quantum noise/error sampler against the
distribution it is supposed to produce, using three independent lenses. A
biased sampler silently weakens the key it helps generate — and the marginal
distribution alone does not catch every defect. The three lenses:

  LENS                 catches                                  research root
  -------------------- ---------------------------------------- ---------------------
  marginal (chi-sq.)   wrong sigma/eta, truncated tail, shifted  generator-anomaly
                       centre, low precision                     testing (from primes)
  serial (neighbours)  correlation between consecutive draws     prime-gap / LOS bias
                       (marginal can look perfect)               of neighbouring primes
  spectral (rhythm)    periodicity / short-period RNG            "hidden rhythm" (Fourier)
                       (identifies the period)

Supported target distributions:
  - CBD (Centred Binomial), eta=2 or 3   -> ML-KEM/Kyber noise (NIST FIPS 203)
  - discrete Gaussian D(Z, sigma)        -> Falcon / FrodoKEM (and historic BLISS)

HONEST SCOPE: this is a statistical quality gate. It certifies that a sampler's
OUTPUT matches the target distribution and is independent and aperiodic. It does
NOT prove the implementation is constant-time or side-channel free (a separate,
complementary audit), and it is validated on synthetic samplers — not yet run
against a production ML-KEM/Falcon build. It is a defensive QA tool: run it on
YOUR OWN sampler output.

Usage:
  python src/pqcq.py selftest
  python src/pqcq.py certify samples.txt --dist cbd --eta 2
  python src/pqcq.py certify samples.txt --dist gaussian --sigma 4.0 [--json]

Input file: integer samples, one per line or whitespace/comma separated.
"""
import sys, os, json, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pqc_certify import certify           # runs the three lenses
import pqc_certify                          # for the selftest demo


# ---------------- input ----------------
def read_samples(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    toks = text.replace(",", " ").split()
    out = []
    for t in toks:
        try:
            out.append(int(t))
        except ValueError:
            try:
                out.append(int(round(float(t))))
            except ValueError:
                pass
    return out


# ---------------- report ----------------
# The research modules label the lenses in Portuguese; present them in English
# for the flagship CLI without touching those modules.
_LENS_LABEL = {
    "marginal": "marginal (distribution)",
    "serial": "serial (neighbours)",
    "espectral": "spectral (rhythm)",
}
def _label(key):
    k = key.strip()
    for stem, lab in _LENS_LABEL.items():
        if k.startswith(stem):
            return lab
    return k


def certify_file(path, dist, sigma, eta, as_json=False):
    samples = read_samples(path)
    n = len(samples)
    if n < 2000:
        msg = (f"only {n} samples — need >= 2000 for a meaningful chi-square/serial/"
               f"spectral verdict. Collect more sampler output.")
        if as_json:
            print(json.dumps({"file": path, "error": msg, "n": n}))
        else:
            print(f"  [!] {msg}")
        return 2

    kind = "gaussian" if dist == "gaussian" else "cbd"
    certified, res = certify(samples, kind=kind, sigma=sigma, eta=eta)
    target = (f"discrete Gaussian D(Z, sigma={sigma})" if kind == "gaussian"
              else f"Centred Binomial CBD(eta={eta})")

    if as_json:
        print(json.dumps({
            "file": path, "n": n, "target": target, "certified": certified,
            "lenses": {_label(k): {"pass": bool(v[0]), "detail": v[1]} for k, v in res.items()},
        }, indent=2))
        return 0 if certified else 1

    print("=" * 74)
    print("  PQCQ - sampler certification report")
    print("=" * 74)
    print(f"  file:     {path}")
    print(f"  samples:  {n:,}")
    print(f"  target:   {target}")
    print("-" * 74)
    for lens, (ok, det) in res.items():
        print(f"    [{'PASS' if ok else 'FAIL'}]  {_label(lens):<22}  {det}")
    print("-" * 74)
    if certified:
        print("  >>> CERTIFIED - output matches the target, is serially independent")
        print("      and shows no periodicity.")
    else:
        failed = [_label(k) for k, v in res.items() if not v[0]]
        print(f"  >>> NOT CERTIFIED - failed lens/lenses: {', '.join(failed)}.")
        print("      Do not ship this sampler to production; investigate the flagged axis.")
    print("-" * 74)
    print("  Scope: statistical QA of the sampler OUTPUT (distribution + independence")
    print("  + aperiodicity). Complements - does not replace - a constant-time /")
    print("  side-channel review. Run on your own sampler output. MIT, runs locally.")
    print("=" * 74)
    return 0 if certified else 1


def main():
    p = argparse.ArgumentParser(prog="pqcq", description="Post-quantum sampler certification")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("selftest", help="run the built-in demo (4 samplers, 3 lenses)")

    c = sub.add_parser("certify", help="certify a file of sampler output")
    c.add_argument("file")
    c.add_argument("--dist", choices=["cbd", "gaussian"], default="cbd",
                   help="target distribution (default: cbd)")
    c.add_argument("--eta", type=int, default=2, choices=[2, 3],
                   help="CBD parameter eta (ML-KEM uses 2 or 3; default 2)")
    c.add_argument("--sigma", type=float, default=4.0,
                   help="discrete-Gaussian sigma (default 4.0)")
    c.add_argument("--json", action="store_true", help="machine-readable output")

    args = p.parse_args()
    if args.cmd == "selftest":
        pqc_certify.main()
        return 0
    if args.cmd == "certify":
        return certify_file(args.file, args.dist, args.sigma, args.eta, args.json)
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
