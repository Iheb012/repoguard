# Devlog

## Week 1
- [y] Repo created, both partners have access
- [y] Contract (`models.py`) agreed
- Notes:
## Week 2 Planning
* **What I learned:** Many advanced threats (like hidden Unicode or steganography) are incredibly hard to catch with basic static analysis, which explains why tools like `ghsafe` produce so many false positives when they try to guess intent. 
* **Strategy:** By prioritizing the 6 "easiest to detect" patterns (like `postinstall` hooks and `curl | sh`), we can build a highly accurate first version of our scanner that catches the most common malware vectors without overwhelming the user with noise.