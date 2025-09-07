# Password Strength Analyzer with Custom Wordlist Generator

##  Objective
A Python tool to *analyze password strength* and *generate custom wordlists*, developed as part of a cybersecurity internship project.

---

## Features
- Evaluate password strength:
  - Score (0–10)
  - Entropy estimate
  - Strength label (Weak / Medium / Strong)
  - Human-readable advice
- Generate custom wordlists from:
  - Name
  - Date of Birth
  - Pet name
  - Extra keywords
- Includes:
  - Leetspeak variations (e.g., a → @, 4, s → $, 5)
  - Year patterns (e.g., 2000–2025)
- Export wordlists in .txt format
- Simple *Command Line Interface (CLI)*

---

##  Tools Used
- *Language:* Python 3.8+  
- *Libraries:* argparse, re, itertools, math, datetime (all built-in)

---

##  Installation
Clone the repository and go into the project folder:
```bash
git clone <your-repo-link>
cd password-strength-analyzer
