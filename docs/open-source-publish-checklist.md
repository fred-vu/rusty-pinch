# Rusty Pinch Public Publish Checklist

Use this checklist before pushing `rusty-pinch/` to a public repository.

## 1. Scope and license

- Confirm repository scope is only `rusty-pinch/`.
- Confirm `LICENSE` is present and matches intended usage terms.
- Confirm `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` are present.
- Review `docs/public-docs-manifest.md` and publish only approved docs.

## 2. Remove sensitive/runtime artifacts

Do not publish:

- `.env`
- `data/`
- `workspace/`
- `target/`
- deploy runtime env files:
  - `deploy/container/rusty-pinch.env`
  - `deploy/container/rusty-pinch.rpi.env`

Quick checks:

```bash
cd rusty-pinch
git status --short
```

```bash
cd rusty-pinch
find . -maxdepth 3 -type f \( -name ".env" -o -name "*.jsonl" -o -name "latest.json" \)
```

## 3. Secret scan

```bash
cd rusty-pinch
rg -n "API_KEY=|TOKEN=|SECRET=|PASSWORD=|sk-[A-Za-z0-9]" . \
  --glob '!target/**' --glob '!assets/**' --glob '!Cargo.lock'
```

All findings must be templates, tests, or docs examples only.

## 4. Validation

```bash
cd rusty-pinch
cargo fmt --all
cargo check
cargo test
```

## 5. Push only subfolder (`rusty-pinch/`)

From monorepo root:

```bash
git subtree split --prefix=rusty-pinch -b rusty-pinch-publish
git remote add rusty-pinch-origin <NEW_GITHUB_REPO_URL>
git push rusty-pinch-origin rusty-pinch-publish:main
```

Optional cleanup:

```bash
git branch -D rusty-pinch-publish
```

## 6. Post-push checks

- Verify GitHub repository contains only Rusty Pinch files.
- Verify no runtime state or secrets are visible in latest commit.
- Enable branch protection and required checks.
