# Working together

1. Never commit directly to `main`. One task = one branch (`feat/short-name`) = one pull request.
2. Every PR is reviewed by the *other* partner before merge.
3. Tests must pass (`pytest`) and `ruff check .` must be clean.
4. Changes to `src/repoguard/models.py` need both partners' approval.
5. Small commits, clear messages ("Add base64 blob rule", not "update").
6. Never commit tokens or secrets. Use environment variables (`GITHUB_TOKEN`).
7. Test fixtures must be **harmless** imitations of bad patterns, never working malware.
8. Weekly: Monday plan (20 min), Thursday/Friday demo + merge (20 min). Notes go in `docs/devlog.md`.
