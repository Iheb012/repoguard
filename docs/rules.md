# Threat Techniques: Fake Job Interview & Coding Test Malware

## Week 1: Priority Rules for Implementation

This document outlines 10 techniques used by attackers (often associated with the "Contagious Interview" campaign) to compromise developer environments through fake job offers, coding tests, and malicious repositories.

| # | Technique & Hiding Location | Static Detection Pattern / Check | Severity | Explanation & Advice |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Malicious npm Lifecycle Scripts**<br>Hides in: `package.json` (`postinstall`, `preinstall`, or `prepare` fields)  | Look for `"postinstall": "node setup.js"` or `"preinstall": "curl ... \| sh"`. Any script that downloads or executes code during installation. | **High** | The script runs automatically when a developer runs `npm install` to set up the project. It often fetches a second-stage payload from a remote server.<br>**Advice:** Do not run `npm install` on untrusted projects. Inspect `package.json` scripts manually first. |



| **2** | **VS Code Auto-Run Tasks**<br>Hides in: `.vscode/tasks.json`  | Check for `"runOn": "folderOpen"` combined with a `"command"` that executes a shell script or downloads a file. | **High** | Simply opening the project folder in VS Code triggers the malicious task automatically (if the user clicks "Trust"). This bypasses the need for `npm install`.<br>**Advice:** Never trust a workspace you do not fully understand. Regularly audit `.vscode` folders. |




| **3** | **Remote Payload Download & Execution**<br>Hides in: Any `.js`, `.py`, or `.sh` file (often `install.js`, `setup.js`, or `launcher.py`) | Look for `require('https').get(...)` or `fetch(...)` combined with `eval()`, `Function()`, or `exec()` immediately afterward. | **High** | Attackers avoid embedding the full malware in the repo. Instead, they download it dynamically from their C2 server to evade static analysis and allow easy updates.<br>**Advice:** Flag any code that downloads and executes remote content without integrity checks. |



| **4** | **Base64 Obfuscation + Eval**<br>Hides in: `.js` files, often disguised as configuration or test data  | Look for long strings decoded via `Buffer.from(..., 'base64')` or `atob()` that are immediately passed to `eval()` or `Function()`. | **Medium** | The actual malicious logic is hidden in a Base64 string to bypass simple string-matching scanners. The `eval` executes the decoded payload.<br>**Advice:** Treat any `eval` or `Function` call with suspicion, especially when paired with encoding/decoding functions. |



| **5** | **Typosquatted Dependencies**<br>Hides in: `package.json` (`dependencies` block) | Look for package names that closely mimic popular libraries (e.g., `chalk-tempalte` instead of `chalk-template`, `axois-utils` instead of `axios-utils`). | **Medium** | Attackers publish packages with names nearly identical to legitimate ones, hoping a developer will make a typo during installation or copy a malicious `package.json` without noticing.<br>**Advice:** Double-check dependency names before installing. Use `npm audit` or lockfiles. |



| **6** | **Steganographic Payloads in Assets**<br>Hides in: Image files (`.svg`, `.woff2`, `.png`)  | Check asset files that are unusually large or contain suspicious non-binary strings. Look for JavaScript code that reads image data and passes it to `eval` or `atob`. | **High** | Malware is hidden inside seemingly harmless font or image files. The loader code extracts the hidden script from the asset and executes it, evading file-extension-based detection.<br>**Advice:** Be suspicious of any code that reads binary asset files and performs dynamic execution. |



| **7** | **Hidden Unicode / Homoglyph Attacks**<br>Hides in: Any source code file (`.js`, `.py`, `.json`) | Look for invisible and bidirectional characters: U+200B to U+200F, U+2060, U+FEFF in the middle of a file, U+202A to U+202E, and U+2066 to U+2069. | **Medium** | Attackers use invisible bidirectional characters to make code appear differently than how it executes (Trojan Source attacks) or to hide payloads.<br>**Advice:** Use IDE extensions that highlight invisible Unicode characters. |



| **8** | **`curl \| sh` / `wget \| sh` Chains**<br>Hides in: `package.json` scripts, `.sh` files, or `Dockerfile`  | Look for patterns like `curl http://... \| bash` or `wget -O- ... \| sh` in any executable script or configuration file. | **High** | A classic technique: download a remote shell script and execute it immediately without saving or verifying it. This gives the attacker full control.<br>**Advice:** Never pipe remote content directly into a shell. Download, inspect, and then execute if necessary. |



| **9** | **`pull_request_target` Workflow Abuse**<br>Hides in: `.github/workflows/*.yml`  | Check for `on: pull_request_target` combined with `actions/checkout@...` that checks out the PR's head SHA (untrusted code). | **high** | This GitHub Actions trigger runs in the context of the base repository with access to secrets. If it checks out attacker code, the attacker can steal secrets or push malicious code.<br>**Advice:** Avoid `pull_request_target` with untrusted code. Use `pull_request` instead, or implement strict code review and sandboxing. |



| **10** | **Environment Variable Exfiltration**<br>Hides in: Any `.js`, `.py` file (often in `postinstall` or main entry point)  | Look for `process.env` being sent to a remote URL via `fetch`, `axios`, or `requests.post`. | **High** | Attackers steal API keys, tokens, and credentials stored in environment variables by sending the entire `process.env` object to their server.<br>**Advice:** In untrusted projects, run code in a sandbox or a container without sensitive environment variables. |

## Additional Context
*   **Campaign:** These techniques are heavily associated with the **"Contagious Interview"** campaign (attributed to North Korean actors), which targets developers via fake job offers on LinkedIn, Upwork, and Discord .
*   **Malware Families:** Common payloads include **BeaverTail** (infostealer), **InvisibleFerret** (backdoor), and **OtterCookie** (RAT).
*   **Safety:** This document is for defensive research only. Do not download or execute real malware.

---

## Week 2: Priority Rules for Implementation

Out of the 10 techniques researched, the following 6 have been selected for Week 2 implementation. These were chosen because they are the easiest to detect using simple static patterns, Regex, or basic file checks.

1. **Technique 1: Malicious npm Lifecycle Scripts** (Check `package.json` for `postinstall`, `preinstall`, `prepare`).
2. **Technique 2: VS Code Auto-Run Tasks** (Check `.vscode/tasks.json` for `"runOn": "folderOpen"`).
3. **Technique 4: Base64 Obfuscation + Eval** (Regex search for `eval()` paired with `Buffer.from(..., 'base64')` or `atob()`).
4. **Technique 7: Hidden Unicode / Homoglyph Attacks** (Scan files for non-ASCII characters outside of standard strings/comments).
5. **Technique 8: `curl | sh` / `wget | sh` Chains** (Regex search for `curl .* \| (bash|sh)` in scripts).
6. **Technique 10: Environment Variable Exfiltration** (Regex search for `process.env` combined with network calls like `fetch` or `axios.post`).

