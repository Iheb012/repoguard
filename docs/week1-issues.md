# Starter GitHub issues (copy each into GitHub Issues)

## Both
- Agree and review `models.py` contract
- Enable branch protection on `main` (require PR + 1 review)

## Partner A (Detection Engine)
- Run GuardDog, sketchy, ghsafe on 3-4 repos and write findings in `docs/research.md`
- List 10 techniques used by fake-interview malware in `docs/rules.md`
- Improve file walker: skip binaries and huge files
- Add rules: curl-pipe-shell, very long lines, hidden Unicode characters

## Partner B (Repo Intelligence and UX)
- Test GitHub API: fetch file tree + file contents (with and without token)
- Add `fetch_repo(url)` skeleton in `fetcher/github.py`
- Terminal report with colors by severity
- Document how risk points are assigned in `scoring.py`
