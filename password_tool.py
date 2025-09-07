#!/usr/bin/env python3
"""
Password Strength Analyzer with Custom Wordlist Generator
- Analyze password strength (Weak / Medium / Strong).
- Generate custom wordlists using user details (name, date of birth, pet, etc.).
- Support leetspeak substitutions and year patterns; export to .txt.
- Simple CLI interface.

Usage examples:
  python password_tool.py analyze --password "P@ssw0rd123!"
  python password_tool.py generate --name "Sadhana" --dob 2004-11-10 --pet "bruno" --extra "forensics,india" --years 2000-2025 --out wordlist.txt
  python password_tool.py both --password "Hello@2024" --name "Sadhana" --dob 2004-11-10 --pet "bruno" --out wordlist.txt
"""
import argparse
import itertools
import math
import re
from datetime import datetime
from typing import List, Set

COMMON_PATTERNS = [
    "password", "passw0rd", "qwerty", "123456", "111111", "letmein",
    "iloveyou", "admin", "welcome", "dragon", "monkey", "shadow",
    "sunshine", "football", "princess", "login", "abc123", "000000"
]

LEET_MAP = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "b": ["b", "8"]
}

SEPARATORS = ["", ".", "_", "-", "@"]

def char_variety(password: str) -> int:
    classes = 0
    if re.search(r"[a-z]", password): classes += 1
    if re.search(r"[A-Z]", password): classes += 1
    if re.search(r"[0-9]", password): classes += 1
    if re.search(r"[^a-zA-Z0-9]", password): classes += 1
    return classes

def entropy_bits(password: str) -> float:
    space = 0
    space += 26 if re.search(r"[a-z]", password) else 0
    space += 26 if re.search(r"[A-Z]", password) else 0
    space += 10 if re.search(r"[0-9]", password) else 0
    space += 33 if re.search(r"[^a-zA-Z0-9]", password) else 0
    space = max(space, 1)
    return len(password) * math.log2(space)

def sequence_or_repeat(password: str) -> bool:
    if re.search(r"(.)\1{2,}", password):  # 3+ repeats
        return True
    sequences = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789"]
    low = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in low:
                return True
    return False

def contains_common_patterns(password: str) -> bool:
    low = password.lower()
    return any(p in low for p in COMMON_PATTERNS)

def score_password(password: str) -> dict:
    if not password:
        return {"score": 0, "label": "Weak", "reason": "Empty password."}
    length = len(password)
    variety = char_variety(password)
    entropy = entropy_bits(password)
    seq_rep = sequence_or_repeat(password)
    common = contains_common_patterns(password)

    score = 0
    if length >= 16: score += 3
    elif length >= 12: score += 2
    elif length >= 8: score += 1

    score += variety - 1
    if entropy >= 80: score += 3
    elif entropy >= 60: score += 2
    elif entropy >= 40: score += 1

    if seq_rep: score -= 2
    if common: score -= 2

    score = max(0, min(10, score))

    if score >= 8:
        label = "Strong"
    elif score >= 5:
        label = "Medium"
    else:
        label = "Weak"

    reasons = []
    if length < 12: reasons.append("Increase length to 12–16+ characters.")
    if variety < 3: reasons.append("Use a mix of upper, lower, digits, and symbols.")
    if seq_rep: reasons.append("Avoid sequences (e.g., 1234, abcd) and repeated characters.")
    if common: reasons.append("Avoid common patterns like 'password', '123456', etc.")
    if not reasons: reasons.append("Good entropy and character variety detected.")

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy, 2),
        "length": length,
        "variety_classes": variety,
        "advice": reasons
    }

def normalize_tokens(*values: str) -> List[str]:
    tokens: Set[str] = set()
    for v in values:
        if not v:
            continue
        parts = re.split(r"[^\w]+", str(v).strip())
        for p in parts:
            if not p:
                continue
            tokens.add(p.lower())
            tokens.add(p.capitalize())
            tokens.add(p.upper())
    return [t for t in tokens if t]

def leet_variants(token: str) -> Set[str]:
    def expand_char(c):
        opts = LEET_MAP.get(c.lower())
        return opts if opts else [c]
    choices = [expand_char(c) for c in token]
    return set("".join(p) for p in itertools.product(*choices))

def year_range(years: str) -> List[str]:
    years = years.strip()
    if "-" in years:
        start, end = years.split("-", 1)
        s, e = int(start), int(end)
        if s > e: s, e = e, s
        return [str(y) for y in range(s, e+1)]
    else:
        return [str(int(years))]

def generate_wordlist(name: str, dob: str, pet: str, extra: List[str], years: str, limit: int) -> List[str]:
    tokens = []
    tokens.extend(normalize_tokens(name, pet))
    tokens.extend(normalize_tokens(*extra))
    if dob:
        try:
            d = datetime.strptime(dob, "%Y-%m-%d")
            tokens.extend([f"{d.day:02d}", f"{d.month:02d}", str(d.year)])
            tokens.extend([f"{d.day}", f"{d.month}", str(d.year % 100).zfill(2)])
        except ValueError:
            pass
    tokens = list(dict.fromkeys(t for t in tokens if t))
    yrs = year_range(years) if years else []
    wl = set()
    for t in tokens:
        for v in leet_variants(t):
            wl.add(v)
            for y in yrs:
                for sep in SEPARATORS:
                    wl.add(f"{t}{sep}{y}")
                    wl.add(f"{y}{sep}{t}")
    wl = [w for w in wl if 3 <= len(w) <= 32]
    wl = sorted(wl)
    if limit:
        wl = wl[:limit]
    return wl

def cmd_analyze(args):
    res = score_password(args.password)
    print("Password Analysis")
    print("------------------")
    print(f"Length          : {res['length']}")
    print(f"Variety Classes : {res['variety_classes']} / 4")
    print(f"Entropy (bits)  : {res['entropy_bits']}")
    print(f"Score           : {res['score']} / 10")
    print(f"Strength        : {res['label']}")
    print("Advice:")
    for a in res["advice"]:
        print(f"- {a}")

def cmd_generate(args):
    extras = [e.strip() for e in (args.extra or "").split(",") if e.strip()]
    wl = generate_wordlist(
        name=args.name or "",
        dob=args.dob or "",
        pet=args.pet or "",
        extra=extras,
        years=args.years or "",
        limit=args.limit or 0
    )
    out_path = args.out or "wordlist.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for w in wl:
            f.write(w + "\n")
    print(f"Generated {len(wl)} candidates -> {out_path}")

def cmd_both(args):
    cmd_analyze(args)
    print()
    cmd_generate(args)

def build_parser():
    p = argparse.ArgumentParser(description="Password Strength Analyzer & Wordlist Generator")
    sub = p.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("analyze", help="Analyze password strength")
    pa.add_argument("--password", required=True)
    pa.set_defaults(func=cmd_analyze)

    pg = sub.add_parser("generate", help="Generate custom wordlist")
    pg.add_argument("--name")
    pg.add_argument("--dob", help="Date of birth YYYY-MM-DD")
    pg.add_argument("--pet")
    pg.add_argument("--extra")
    pg.add_argument("--years", help="Year or range e.g., 2000-2025")
    pg.add_argument("--limit", type=int)
    pg.add_argument("--out", help="Output file")
    pg.set_defaults(func=cmd_generate)

    pb = sub.add_parser("both", help="Analyze password and generate wordlist")
    pb.add_argument("--password", required=True)
    pb.add_argument("--name")
    pb.add_argument("--dob")
    pb.add_argument("--pet")
    pb.add_argument("--extra")
    pb.add_argument("--years")
    pb.add_argument("--limit", type=int)
    pb.add_argument("--out")
    pb.set_defaults(func=cmd_both)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if _name_ == "_main_":
    main()
