# RepoGuard

A **static** scanner that checks a GitHub repository for signs of malware *before* you clone,
install, or open it. Built around one real threat: **fake job-interview / coding-test repos**
that run malicious code when you `npm install` or open the folder in your editor.

> Status: v0.1 (early development). Risk scores are warnings, not proof.

## Why another scanner?
Tools like ghsafe, Flagrix, sketchy, GuardDog and Semgrep already exist. RepoGuard focuses on:
- the interview-scam niche,
- places general scanners overlook (`postinstall` scripts, `.vscode/tasks.json`, `.devcontainer`...),
- repo/author reputation signals,
- plain-language explanations ("what to do"), and
- a *measured* false-positive rate.

## Safety principle
RepoGuard **never executes, imports, or installs** anything from a scanned repo. It only reads text.

## Install (development)
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
repoguard scan tests/fixtures
```

## Architecture
| Module | Owner | Role |
|---|---|---|
| `scanner/`, `rules/` | Partner A | Detection engine |
| `fetcher/`, `reputation/`, `scoring.py`, `report/`, `cli.py` | Partner B | Repo intelligence + UX |
| `models.py` | Both | Shared contract (change only via PR reviewed by both) |

## Roadmap
See `docs/plan.md` and the GitHub Issues board.

## License
MIT
