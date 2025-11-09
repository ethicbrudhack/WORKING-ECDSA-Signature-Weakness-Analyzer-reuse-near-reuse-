# WORKING-ECDSA-Signature-Weakness-Analyzer-reuse-near-reuse-
A fast, scriptable tool to **scan ECDSA (secp256k1) signatures** for RNG mistakes: - **exact nonce reuse** (`k` reused → identical `r`) - **near-reuse** (very similar `r` values → likely `k1 ≈ k2`)
