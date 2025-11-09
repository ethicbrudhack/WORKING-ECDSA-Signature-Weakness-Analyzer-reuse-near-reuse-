#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analiza podpisów ECDSA z wykrywaniem reuse i near-reuse nonce.
Rozszerzona wersja: grupowanie po adresie/pubkey, analiza entropii, histogram LSB.
"""

import sys, random, argparse, hashlib, math
from collections import defaultdict, Counter
import ecdsa

# --- Stałe ---
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DEFAULT_SAMPLE = 1.0
DEFAULT_MAX_PAIRS = 500000
DEFAULT_BITDIFF = 8

# --- Pomocnicze funkcje ---
def modinv_safe(a, mod=n):
    a = a % mod
    if a == 0:
        return None
    try:
        return pow(a, -1, mod)
    except ValueError:
        return None

def hamming_distance(x, y):
    return bin(x ^ y).count("1")

def entropy(values):
    """Entropia Shannona w bitach."""
    if not values:
        return 0.0
    c = Counter(values)
    total = len(values)
    return -sum((count/total) * math.log2(count/total) for count in c.values())

def base58_encode(b: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(b, byteorder='big')
    res = ""
    while num > 0:
        num, rem = divmod(num, 58)
        res = alphabet[rem] + res
    return res

# --- Parser ---
def parse_signatures_file(path):
    import re
    sigs = []
    total_blocks, skipped = 0, 0

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    block = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("---"):
            if block:
                total_blocks += 1
                entry = parse_block(block)
                if entry:
                    sigs.append(entry)
                else:
                    skipped += 1
                block = []
        else:
            block.append(line)
    if block:
        total_blocks += 1
        entry = parse_block(block)
        if entry:
            sigs.append(entry)
        else:
            skipped += 1

    print(f"[INFO] Wczytano {len(sigs)} poprawnych podpisów z {total_blocks} bloków ({skipped} pominięto).")
    return sigs

def parse_block(lines):
    import re
    entry = {}
    # CSV detection
    if len(lines) == 1 and "," in lines[0]:
        parts = [p.strip() for p in lines[0].split(",")]
        if len(parts) >= 5:
            try:
                entry["address"] = parts[0]
                entry["r"] = int(parts[1], 16)
                entry["s"] = int(parts[2], 16)
                entry["z"] = int(parts[3], 16)
                entry["txid"] = parts[4]
                return entry
            except Exception:
                return None

    for l in lines:
        if any(x in l for x in ["Podatności", "SIGHASH_FLAG", "ratio ≈", "Low-S"]):
            continue
        l = l.strip()
        if re.match(r'^(adres|address|Address)\s*[:=]', l):
            entry["address"] = re.split(r'[:=]', l, 1)[1].strip()
        elif re.match(r'^(txid|TXID)\s*[:=]', l):
            entry["txid"] = re.split(r'[:=]', l, 1)[1].strip()
        elif re.match(r'^[rR]\s*[:=]', l):
            try: entry["r"] = int(re.split(r'[:=]', l, 1)[1].strip(), 16)
            except: pass
        elif re.match(r'^[sS]\s*[:=]', l):
            try: entry["s"] = int(re.split(r'[:=]', l, 1)[1].strip(), 16)
            except: pass
        elif re.match(r'^[zZ]\s*[:=]', l):
            try: entry["z"] = int(re.split(r'[:=]', l, 1)[1].strip(), 16)
            except: pass
    return entry if "r" in entry and "s" in entry and "z" in entry else None

# --- Główne funkcje analityczne ---
def recover_k_from_pair(sig1, sig2):
    sdiff = (sig1["s"] - sig2["s"]) % n
    inv = modinv_safe(sdiff)
    if inv is None: return None
    return ((sig1["z"] - sig2["z"]) * inv) % n

def recover_d_from_k_and_sig(k, sig):
    inv_r = modinv_safe(sig["r"])
    if inv_r is None: return None
    return ((sig["s"] * k - sig["z"]) * inv_r) % n

def compute_uncompressed_pubkey_hex_from_d(d):
    sk = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1)
    return "04" + sk.verifying_key.to_string().hex()

def r_lsb_stats(signatures, bits=16):
    """Statystyka najmłodszych bitów r (LSB) + entropia."""
    if not signatures:
        return {"bits": bits, "mean": 0, "variance": 0, "entropy": 0, "sample_count": 0}
    vals = [(sig["r"] & ((1<<bits)-1)) for sig in signatures]
    mean = sum(vals)/len(vals)
    var = sum((v-mean)**2 for v in vals)/len(vals)
    return {
        "bits": bits,
        "mean": mean,
        "variance": var,
        "entropy": entropy(vals),
        "sample_count": len(vals)
    }

def detect_near_reuse(idx_sig_list, bitdiff=8):
    """
    Szuka par z podobnym r (różnica bitowa <= bitdiff),
    ale pomija identyczne r (różnica == 0).
    """
    pairs = []
    m = len(idx_sig_list)
    for a in range(m):
        for b in range(a+1, m):
            i, sig1 = idx_sig_list[a]
            j, sig2 = idx_sig_list[b]
            dist = hamming_distance(sig1["r"], sig2["r"])
            if 0 < dist <= bitdiff:
                pairs.append({"pair": (i, j), "bitdiff": dist, "sig1": sig1, "sig2": sig2})
    return pairs

# --- MAIN ---
def main(path, sample_frac=1.0, max_pairs=500000, nearreuse=False, bitdiff=8):
    sigs = parse_signatures_file(path)
    total = len(sigs)
    if total == 0:
        print("Brak podpisów.")
        return

    sample_count = max(1, int(total * sample_frac))
    sampled = random.sample(list(enumerate(sigs)), sample_count) if sample_count < total else list(enumerate(sigs))
    print(f"\nWczytano {total} podpisów, użyto próbki {sample_count} ({sample_frac*100:.1f}%).")

    groups = defaultdict(list)
    for i, sig in sampled:
        owner = sig.get("address") or "__unknown__"
        groups[owner].append((i, sig))

    near_found = []
    print("\n=== Analiza ===")
    for owner, idx_list in groups.items():
        print(f"\n📂 Analiza owner='{owner}' ({len(idx_list)} podpisów)")
        if len(idx_list) < 2:
            continue

        if nearreuse:
            print(f"  🔍 Tryb near-reuse (bitdiff ≤ {bitdiff})")
            near_pairs = detect_near_reuse(idx_list, bitdiff)
            if near_pairs:
                print(f"  ⚠️  Znaleziono {len(near_pairs)} par z podobnym r.")
                near_found.extend(near_pairs)
            else:
                print("  — brak podobnych r.")
        else:
            print("  🔍 Tryb klasyczny — szukanie dokładnego reuse (r identyczne).")
            seen = defaultdict(list)
            for i, sig in idx_list:
                seen[sig["r"]].append((i, sig))
            for same_r, items in seen.items():
                if len(items) > 1:
                    print(f"  🎯 reuse r={hex(same_r)} w {len(items)} podpisach!")

    # --- Wyniki near-reuse ---
    if nearreuse and near_found:
        print(f"\n🎯 Znaleziono {len(near_found)} podejrzanych par (near-reuse):")
        with open("results_nearreuse.txt", "w") as f:
            for item in near_found:
                i, j = item["pair"]
                sig1, sig2 = item["sig1"], item["sig2"]
                diff = item["bitdiff"]
                print(f"\n🧩 Para ({i},{j}) różnica {diff} bitów:")
                print(f"  r1={hex(sig1['r'])}\n  r2={hex(sig2['r'])}")
                print(f"  s1={hex(sig1['s'])}\n  s2={hex(sig2['s'])}")
                print(f"  z1={hex(sig1['z'])}\n  z2={hex(sig2['z'])}")
                if sig1.get('address'): print(f"  addr1={sig1['address']}")
                if sig2.get('address'): print(f"  addr2={sig2['address']}")
                print("──────────────────────────────")
                f.write(f"Pair({i},{j}) diff={diff}\n{hex(sig1['r'])}\n{hex(sig2['r'])}\n\n")
        print("\n💾 Zapisano szczegóły do results_nearreuse.txt")

    # --- Statystyki ---
    stats = r_lsb_stats([sig for _, sig in sampled])
    print("\n📊 Statystyka LSB r:")
    print(f"  próbki={stats['sample_count']}, średnia={stats['mean']:.2f}, wariancja={stats['variance']:.2f}, entropia={stats['entropy']:.2f} bitów")

    # analiza wspólnych bitów
    bit_matches = []
    for a in range(len(sampled)-1):
        for b in range(a+1, len(sampled)):
            samebits = 256 - hamming_distance(sampled[a][1]['r'], sampled[b][1]['r'])
            bit_matches.append(samebits)
    avg_common = sum(bit_matches)/len(bit_matches) if bit_matches else 0
    print(f"  🔍 Średnia liczba wspólnych bitów między r: {avg_common:.2f}")

    print("\n✅ Analiza zakończona.")
    if near_found:
        print(f"🎯 Znaleziono {len(near_found)} podejrzanych par (near-reuse).")
    else:
        print("❌ Nie znaleziono near-reuse.")

# --- Uruchomienie ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analiza podpisów ECDSA (reuse / near-reuse).")
    parser.add_argument("file", help="Plik z podpisami (signatures.txt)")
    parser.add_argument("--sample", type=float, default=DEFAULT_SAMPLE, help="Ułamek próbkowania (0–1).")
    parser.add_argument("--maxpairs", type=int, default=DEFAULT_MAX_PAIRS, help="Maksymalna liczba par.")
    parser.add_argument("--nearreuse", action="store_true", help="Włącz analizę near-reuse (podobne r).")
    parser.add_argument("--bitdiff", type=int, default=DEFAULT_BITDIFF, help="Maksymalna liczba różniących się bitów r.")
    args = parser.parse_args()
    random.seed(0xC0FFEE)
    main(args.file, args.sample, args.maxpairs, args.nearreuse, args.bitdiff)
