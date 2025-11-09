# ECDSA Signature Weakness Analyzer (reuse / near-reuse)

A fast, scriptable tool to **scan ECDSA (secp256k1) signatures** for RNG mistakes:
- **exact nonce reuse** (`k` reused → identical `r`)
- **near-reuse** (very similar `r` values → likely `k1 ≈ k2`)
- quick **pairwise recovery attempts** of the private key `d` when feasible

Designed for educational research on weak RNG scenarios (Bitcoin-style signatures).  
**Do not use on data you don’t own.**

---

## ✨ Features

- **Multiple input formats** in one file:
  - Classic blocks:
    ```
    txid: ...
    address: ...
    pubkey: ...
    r: <hex>
    s: <hex>
    z: <hex>
    ----------------------------------
    ```
  - “New” blocks:
    ```
    Adres: ...
    r = <hex>
    s = <hex>
    z = <hex>
    txid = ...
    ----------------------------------
    ```
  - **CSV in one line**:
    ```
    <address>,<r>,<s>,<z>,<txid>
    ```
  - The parser **skips** helper lines like `Podatności: ...`, `SIGHASH_FLAG`, `ratio ≈ ...` etc.

- **Owner grouping** (by `address` or `pubkey`) so signatures from different owners don’t mix.
- **Sampling**: analyze only a fraction of a huge file (`--sample 0.10` = 10%) to speed up.
- **Near-reuse detection** via **Hamming distance** on `r` (`--nearreuse --bitdiff 8`).
- **Pairwise recovery attempts** of `d` when math conditions permit.
- **Progress logs** for big datasets.
- **LSB statistics** of `r` as a quick RNG sanity check.

---

## 🚀 Quick Start

```bash
# 1) Create & activate a virtualenv (optional but recommended)
python3 -m venv venv
source venv/bin/activate     # on Windows: venv\Scripts\activate

# 2) Install dependencies
pip install ecdsa

# 3) Run on your dataset
python3 inteligentnyskrypt.py signatures.txt \
  --sample 0.10 \
  --maxpairs 100000 \
  --nearreuse --bitdiff 8
Dependencies

Python 3.8+

ecdsa (pip install ecdsa)

The script uses only standard library + ecdsa. No SciPy/NumPy required.

🧾 Input File — Examples

Classic block

txid: ed8deb44599bb903...
address: 1Bw1hpkUrTKRmrwJBGdZTenoFeX63zrq33
pubkey: 04bb3736...
r: bb79ffc2b796e2...
s: 5e5723404a0954...
z: 0630f5a43bace4...
----------------------------------


“New” block

Adres: bc1qdmalkt80m78am0mu9zsjjuf6nzjrsf87lw2jqm
r = 70c6c5f514f5...
s = 4194dcfd6d52...
z = 610dbc6d02dd...
txid = 46f1452637a2...
----------------------------------


CSV line

3QK5vQ9hucSg8ZC8Vizq83qEWeHFLAWMud,663f63...,89468b...,599fc0...,3754137...


Lines like Podatności: ..., SIGHASH_FLAG = ..., or comments are automatically ignored.

🧩 What It Detects
1) Exact nonce reuse (k reused)

For ECDSA over secp256k1:

Public base point G, group order n

Sign z with secret d:

Choose random k

Compute R = kG, r = R.x mod n

Compute s = k⁻¹ (z + r·d) mod n

If the same k is reused for two messages (z₁, r, s₁) and (z₂, r, s₂), then:

𝑘
≡
(
𝑧
1
−
𝑧
2
)
⋅
(
𝑠
1
−
𝑠
2
)
−
1
(
m
o
d
𝑛
)
k≡(z
1
	​

−z
2
	​

)⋅(s
1
	​

−s
2
	​

)
−1
(modn)

and then:

𝑑
≡
(
𝑠
1
⋅
𝑘
−
𝑧
1
)
⋅
𝑟
−
1
(
m
o
d
𝑛
)
d≡(s
1
	​

⋅k−z
1
	​

)⋅r
−1
(modn)

The script tries this recovery when it finds suitable pairs.

2) Near-reuse (k1 ≈ k2)

If k₁ and k₂ are very close (e.g., share many leading bits), you often see very similar r.
We detect candidates by Hamming distance:

dist
(
𝑟
1
,
𝑟
2
)
=
popcount
(
𝑟
1
⊕
𝑟
2
)
≤
bitdiff
dist(r
1
	​

,r
2
	​

)=popcount(r
1
	​

⊕r
2
	​

)≤bitdiff

--bitdiff 4–8: very strong indicator

larger values (12–16+) yield more noise (false positives).

The script then tries the reuse-recovery formula anyway (best-effort heuristic).
Full near-reuse attacks may require lattice/HNP methods — out of scope here by design (kept simple & fast).

3) RNG sanity: LSB stats of r

We compute the mean/variance of the lowest 16 bits of r.
Highly skewed values across a big set might hint at RNG biases.

🖥️ Usage
python3 inteligentnyskrypt.py FILE [--sample F] [--maxpairs N] [--nearreuse] [--bitdiff B]


Arguments

FILE — path to your signatures.txt.

--sample F — take only a fraction of the file (0–1). Default: 1.0 (100%).

--maxpairs N — cap max tested pairs per group (when very large). Default: big number.

--nearreuse — enable near-reuse mode (checks similar r via Hamming distance).

--bitdiff B — Hamming threshold for near-reuse (default: 8).

Recommended combos

# Quick scan on 10% of data, check near-reuse with tight threshold
python3 inteligentnyskrypt.py signatures.txt --sample 0.10 --nearreuse --bitdiff 8

# Full scan (can be heavy), allow up to 100k pairs per owner
python3 inteligentnyskrypt.py signatures.txt --maxpairs 100000

📈 Output (sample)
Wczytano 139988 podpisów. Próbka: 13999 (10.0%).

=== Analiza reuse / near-reuse ===

📂 Analiza owner='1Bw1hpkUrTKRmrwJBGdZTenoFeX63zrq33' (523 podpisów)
  🔍 Tryb near-reuse (bitdiff ≤ 8)
  ⚠️  Znaleziono 3 pary z podobnym r.

🧩 Para (2004,2007) | Hamming(r1,r2)=6 bits
  r1=0x..., s1=0x..., z1=0x..., txid1=...
  r2=0x..., s2=0x..., z2=0x..., txid2=...
  → attempt k=(z1-z2)/(s1-s2) mod n OK
    k = 0x...
    d = 0x...
    pubkey match: False

📊 Statystyka LSB r:
  samples=13999, mean=32820.37, variance=356979978.03


If the script prints “Znaleziono … kandydatów d/k”, it found pairs where the simple reuse math produced a consistent d.
If not, it still reports similar-r pairs (near-reuse candidates) and stats.

📐 Math Appendix (Why Hamming on r?)

r = x(k·G) mod n.
For secp256k1, x(·) is nonlinear, but in practice when k values are very close (many shared MSBs), the resulting R = kG points — and their x-coordinates — can be correlated enough that Hamming distance on r is a cheap and effective heuristic filter.

Back-of-the-envelope probability: the chance that two random 256-bit numbers differ in ≤8 bits is

∑
𝑖
=
0
8
(
256
𝑖
)
/
2
256
≈
2
−
247
i=0
∑
8
	​

(
i
256
	​

)/2
256
≈2
−247

So if you see many pairs with bitdiff ≤ 8, it’s very unlikely to be random.

🧠 Performance Tips

Use --sample on huge files (e.g., 0.1 or 0.25) to triage first.

Keep --bitdiff small (e.g., 4–8) for precise near-reuse hits.

Limit pairs per owner with --maxpairs to avoid quadratic explosion.

🔒 Legal & Safety Notice

This tool is for education and research.
Recovering private keys from signatures can expose funds.
Only analyze data you own or are permitted to audit.
No guarantees; use responsibly.

🛠️ Troubleshooting

“No valid signatures parsed”: check your file format; remove non-hex chars in r/s/z.

“Killed / out of memory”: reduce --sample or --maxpairs.

“No results”: try --nearreuse --bitdiff 8, or scan a larger sample.

📦 Minimal Project Structure
.
├── inteligentnyskrypt.py
├── signatures.txt      # your data
└── venv/               # optional virtual environment

📜 License

MIT — see LICENSE (add one if you publish). 
