# Step 3: Research and Testing of Malware Detection Tools

## Overview
This document compares the performance of static analysis tools (GuardDog, ghsafe, and sketchy) on safe, trusted repositories versus controlled, fake malicious scripts. The goal is to identify what these tools catch, what they miss, and how many false positives they generate.

## Test Targets
1. **Control Group (Trusted Repos):** `expressjs/express`, `Ai_Network_Copilot`, `gods-eye-view`, `POURLAFORME`, `rea`.
2. **Fake Malware Sample:** A custom `package.json` with a `postinstall` script pointing to a `setup.js` file containing a harmless base64 encoded string and an `eval()` function.

## Results Table

| Tool | Input type | Caught | Missed | False positives | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GuardDog** | NPM (Directory/Static) | 1. `setup.js` containing Base64 decoding + `eval()` execution.<br>2. `subprocess.run` calls (`ping`, `ipconfig`).<br>3. Environment variable reads. | The `postinstall` trigger in `package.json` was not explicitly flagged during the broad directory scan. Missed context (could not tell `curl` was fetching safe map data). | **High.** Generated 37 risks on a normal home directory (VS Code extensions, Python venv). Flagged 30 risks in `gods-eye-view` and 9 in `Ai_Network_Copilot` for legitimate OS interactions. | Uses Semgrep and YARA. Extremely fast. Zero false positives on `express.js`. Highly sensitive to generic commands like `eval`, `subprocess`, and `os.environ`. |
| **ghsafe** | NPM / Git URLs | 1. `postinstall` script in `package.json` (INST-001).<br>2. `eval()` usage in `setup.js` (OBF-001).<br>3. Base64 decoding in `setup.js` (OBF-005). | Did not miss any of the fake malware indicators. However, it completely missed the malicious behavior during the first failed run (0 files analyzed) due to a pathing issue. | **Extremely High.** Flagged `gods-eye-view` as 100/100 "DANGEROUS" (414 findings) and `rea` as 100/100 (1697 findings) mostly for standard use of environment variables (`process.env`) and generic `child_process` imports. | Excels at producing colorful CLI reports. Highly aggressive with environment variable reads (labels them "Data Exfiltration" / "Crypto Mining" even when reading simple configs). Correctly identified `POURLAFORME` as safe (0 findings). |
| **sketchy** | Repository (Go-based) | 1. Base64 decoding (`base64`).<br>2. Dynamic code execution (`eval-exec`). | **Missed the `postinstall` hook in `package.json` entirely.** Only scans file contents, not the `package.json` lifecycle scripts. | *(Not fully tested in this run, but typically lower than ghsafe as it focuses on specific pairing of capabilities)* | Requires Go to build. Uses capability-based pairing (only flags `eval` if it is paired with `base64`). Very focused and less noisy than ghsafe. |

## Key Takeaways
* **The "Missed" Column:** As noted in the assignment instructions, this is the most valuable column. 
    * **GuardDog** missed the `postinstall` context in a broad scan and missed that `curl` was legitimate.
    * **ghsafe** initially missed the malware entirely due to a pathing error, but once corrected, it successfully caught all 3 malicious indicators.
    * **sketchy** completely missed the `postinstall` hook because it focuses strictly on file contents (like `.js`, `.py`), not `package.json` scripts.
* **False Positives in Context:** `ghsafe` is incredibly aggressive. It flagged over 2,000 "Critical" findings across safe repositories simply because they used `process.env` to read API keys or used `child_process` to run basic scripts. It does not seem to distinguish between legitimate development tasks and malicious behavior. GuardDog is more balanced, only flagging 9-30 risks in the same repositories. `sketchy` uses a "capability pairing" system which helps reduce false positives (e.g., it won't flag `eval` unless it sees it paired with something like `base64`).
* **Control Group Success:** Both GuardDog and ghsafe successfully identified `express.js` and `POURLAFORME` as clean (0 findings). GuardDog is generally more balanced in its reporting, whereas `ghsafe` jumps to a 100/100 risk score very quickly.

## Safety Note
No real malware was downloaded, cloned, or executed during this testing. All malicious samples were fake, harmless scripts created locally for evaluation purposes.