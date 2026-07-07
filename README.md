# HonestKeyAudit

**Post-quantum sampler certification and cryptographic key assurance — make sure the randomness under your keys is honest, from RSA today to ML-KEM/Falcon tomorrow.**

Author: **Cristian Vitorino Rodrigues da Cunha** — independent researcher in analytic number theory & cryptographic assurance
Scientific basis: *A Silver-Phase Barrier for Integer Factorization* — DOI [10.5281/zenodo.14553556](https://doi.org/10.5281/zenodo.14553556)

> **Honest scope.** This is a **defensive statistical QA** toolkit. It certifies that a generator's or sampler's *output* matches the distribution it should, is serially independent, and is aperiodic — and it flags *known* weak-key classes. It does **not** break strong cryptography, and it does **not** replace a constant-time / side-channel review (a complementary audit). It is validated on synthetic samplers and real key corpora; it has **not** yet been run against a production ML-KEM/Falcon build. Run it on **your own** keys and sampler output.

---

## Why this exists: the post-quantum migration is a randomness problem

The world is migrating to post-quantum cryptography. NIST finalized **ML-KEM (FIPS 203)**, **ML-DSA (FIPS 204)** and **SLH-DSA (FIPS 205)** in 2024, and "harvest-now, decrypt-later" has put crypto-agility on every serious security roadmap.

Lattice-based PQC has a soft spot that classical audits miss: **its security depends on the quality of a sampler.** The secret noise/error that forms an ML-KEM or Falcon key must follow an exact distribution. If the sampler is biased — a weak RNG, a truncated tail, a stuck bit, a short period, a subtly correlated state — the key is **silently weakened**, and standard bitstream randomness tests (NIST SP 800-22) do not see it. This is not hypothetical: real sampler-side vulnerabilities have hit lattice schemes (BLISS "Flush, Gauss, and Reload"; Falcon timing leaks).

**HonestKeyAudit certifies the sampler.** And because the same method — *test the distribution a generator actually emits* — also audits classical RSA/ECC key populations, one toolkit covers the whole migration: your RSA/ECC estate today, your PQC samplers as you adopt them.

---

## Flagship: PQCQ — post-quantum sampler certification (`src/pqcq.py`)

Point it at a file of your sampler's output and it certifies that output through **three independent lenses**, each catching a defect class the others miss. Two lenses are novel contributions from the underlying research (serial and spectral), which is why they catch bugs a plain distribution test does not.

| Lens | Catches | Research root |
|---|---|---|
| **marginal** (χ²) | wrong σ/η, truncated tail, shifted centre, low precision | generator-anomaly testing (from primes) |
| **serial** (neighbours) | correlation between consecutive draws — *marginal can look perfect* | prime-gap / Lemke-Oliver–Soundararajan bias |
| **spectral** (rhythm) | periodicity / short-period RNG (**identifies the period**) | "hidden rhythm" (Fourier) |

Supported targets: **CBD (centred binomial), η = 2 or 3** — the ML-KEM/Kyber noise — and **discrete Gaussian D(ℤ, σ)** — Falcon / FrodoKEM (and historic BLISS).

```bash
python src/pqcq.py selftest                                   # 4 samplers, 3 lenses — demo
python src/pqcq.py certify samples.txt --dist cbd --eta 2     # ML-KEM noise output
python src/pqcq.py certify samples.txt --dist gaussian --sigma 4.0 [--json]
```

Real run on the included examples (50 000 samples each):

```
  [PASS]  marginal (distribution)   chi2=20.9(df=30) p=8.9e-01     # good Gaussian sampler
  [PASS]  serial (neighbours)       autocorr=-0.0008  z=-0.2
  [PASS]  spectral (rhythm)         g=11.8 p=1.9e-01
  >>> CERTIFIED

  [FAIL]  marginal (distribution)   chi2=984.6(df=30) p=9.1e-188   # σ off by 10%
  >>> NOT CERTIFIED - failed lens/lenses: marginal (distribution).
```

The demo proves each lens independently: a **σ-error** trips the marginal lens; a **sticky/correlated** sampler with a *perfect* marginal distribution is caught **only** by the serial lens; a **short-period RNG** is caught by the spectral lens, which reports the detected period (~1009). `--json` makes it a CI gate (exit code 0 = certified, 1 = rejected).

*Companion QA modules:* `pqc_gaussian_qa.py`, `pqc_sampler_qa.py` (CBD), `pqc_serial_qa.py`, `pqc_spectral_qa.py` — each runnable standalone with its own demo.

---

## Generator-anomaly & drift monitoring — the population lens (`src/gen_anomaly.py`, `src/drift_monitor.py`)

The same idea, applied to **key populations** instead of single keys. Every other tool checks each key against known weak classes; this checks a *population* against the distribution proper generation should follow — flagging a **biased generator** before it becomes the next ROCA.

- **Residue uniformity** (χ² of `N mod m`) — modular RNG bias.
- **Silver-phase / Hecke equidistribution** (KS on `φ(N) = frac(log_δ N)`) — the object from the published no-go theorem; catches a bias on the *logarithmic axis* (low-entropy key sizing) that residue and per-key checks do not see.

**Continuous drift monitoring (`drift_monitor.py`)** is the productized form: fingerprint a *trusted* generator's population, then flag every new batch that **drifts** — a silent generator change, entropy degradation, or **supply-chain contamination**. Validated: no false alarm on the same generator; drift detected on a generator swap and on 20% contamination (foreign keys flagged individually via the FIPS/OpenSSL top-2-bits floor, plus two-sample tests on the silver phase, leading value, and residues).

---

## Also included: classical RSA & ECC weak-key classes

The migration is gradual — your RSA/ECC keys must stay safe meanwhile. Same toolkit, standard detectors.

**RSA (`src/rsa_audit.py`, `src/keyaudit.py`, `src/roca.py`):** Fermat (close primes), batch-GCD (shared factor), mod-M bias, **ROCA** (CVE-2017-15361), p−1 smoothness, **Wiener** (small `d`). AUC = 1.00, zero false positives on synthetic corpora.

**ECC (`src/ecc_audit.py`):** on-curve / invalid-curve, non-standard curve, small subgroup, anomalous (Smart), MOV, and **ECDSA nonce reuse** — with private-key recovery demonstrated to prove why reuse is fatal (the PS3 / wallet class).

**Scale study (`src/batchgcd.py`):** Bernstein's batch-GCD (product + remainder tree, `O(n log²n)`), ≈25k moduli/s with `gmpy2`, scaling to millions. Ingests a moduli file, a folder of PEM/DER certs, or live GitHub SSH keys.

```bash
# One app for real keys — PEM/DER X.509, RSA/EC public keys, OpenSSH keys (public or private):
python src/keyaudit.py /path/to/cert.pem
python src/keyaudit.py /path/to/keys_folder/     # scans all keys + cross-key batch-GCD
python src/webapp.py                             # local web UI at http://localhost:8000
```

---

## The research behind it

HonestKeyAudit is the applied side of the **Projeto Prata** research programme, which followed a hand-built spreadsheet of prime "voids" to the frontier of the Riemann Hypothesis, with honest computational verification at every step. Its central publishable result is **the Barrier**: recovering the silver-coordinate phase of a factor is polynomial-time equivalent to factoring — a rigorous *no-go* theorem, generalized to any continuous logarithmic-scale lens. That negative result is a **security guarantee**: the audit lens provably cannot become an attack. The same equidistribution/discrepancy methods that proved it are the lenses this toolkit runs. See the paper: DOI [10.5281/zenodo.14553556](https://doi.org/10.5281/zenodo.14553556).

## Roadmap

Uniform-rejection sampler QA (ML-DSA/Dilithium), signed PDF certification reports, `pip install` packaging, Debian-2008 weak-key blacklist, lattice-based biased-nonce recovery (Minerva/LadderLeak), and validation runs against reference PQC implementations (liboqs).

## Ethics

Defensive use only. Run on **your own** keys and sampler output, synthetic data, or public research datasets with responsible disclosure — never against third-party keys or systems without authorization.

## License

[MIT](LICENSE) — free to use, with attribution.

---

*Built honestly. Every claim is computationally verified; successes and failures are documented alike.*
