# Forgejo Actions (CI)

Workflows in this directory are **thin callers**. Tag / publish / checks logic lives in
[`faicel/central_ci`](https://code.bhk-itsolutions.com/faicel/central_ci) (`create_tag_on_dev`,
`create_tag_on_main`, `publish_on_tag`, `rust_crate_checks`, `validate_flow`).
Only triggers and crate-specific inputs (`test_command`, `enable_deny`, …) stay here.

Sigil-specific note: every caller passes `test_command: bash scripts/test.sh`
because the plain `cargo test` default is invalid for this crate — the empty
feature set is rejected at compile time by design, and the authoritative gate is
the locked feature matrix plus rustdoc and embedded-target cross-checks. That
script also carries the feature clippy matrix (all features, sensor, gateway),
which the shared gate does not cover (it lints with default features only).
`cargo deny` runs inside the shared gate (`enable_deny`, default true); the
local wrapper is `scripts/deny-check.sh`.

## Publish flow (happy path)

| Branch | Tag shape | Registry | Forgejo release |
| --- | --- | --- | --- |
| `dev` | `vX.Y.Z-rc` | `forgejorc` (unstable / `homeiot-rc`) | prerelease |
| `staging` | — (merge gate only) | — | — |
| `main` | `vX.Y.Z` | `forgejo` (stable / `homeiot`) | release |

`Cargo.toml` / `CHANGELOG.md` always hold the **stable** base version (e.g. `1.2.0`).
The stable/unstable split is done by **registry**, not by rewriting the crate version.

1. Bump `Cargo.toml` + `CHANGELOG` (required: each version publishes once per registry).
2. Feature branch → checks via `check-on-feature-branch.yml`.
3. Merge to `dev` → `create-tag-on-dev.yml` creates `vX.Y.Z-rc` (skips if the tag already exists).
4. Tag push → `publish-on-tag.yml` publishes to `forgejorc` (client staging can pin this version).
5. Merge `dev` → `staging` → `main` (`staging` does not tag or publish).
6. Push to `main` → `create-tag-on-main.yml` creates `vX.Y.Z` **and** ensures `release/X.Y` exists.
7. Tag push → `publish-on-tag.yml` publishes to `forgejo` (client prod).
   Note: the callee defaults `enable_tag_check` to `false` because the tag
   already exists (it is the trigger); the tag check stays enabled on feature /
   `dev` / `main` pushes to prevent duplicate releases.

`validate-branch-flow.yml` enforces PR direction via shared `faicel/central_ci` → `validate_flow.yml`:
`* → dev`, `dev → staging`, `staging → main`.

Keep `Cargo.toml` and the latest `CHANGELOG.md` heading in sync (see `scripts/check-version-sync.sh`).

Registries are defined in [`.cargo/config.toml`](../.cargo/config.toml).

## Maintenance branches (`release/X.Y`)

### Why

`dev` keeps moving (features → next minor). A client or prod may stay on `1.2.0`.
If a bug is found in `1.2.0` while `dev` already has `1.3.0` work, fixing only on `dev`
would force the client to take unwanted features. A **`release/1.2`** line lets you
ship `1.2.1` without `1.3.0`.

```text
main / tag v1.2.0 ──► release/1.2 ──► 1.2.1, 1.2.2   (hotfixes only)
                  └──► dev ─────────► 1.3.0-rc …     (features)
```

### Automation on `main`

When `create-tag-on-main.yml` publishes the first stable `vX.Y.Z` of a minor line, it
creates `release/X.Y` at that commit (via the shared central_ci implementation).

- If `release/X.Y` **already exists**, CI leaves it unchanged (no force-update).
- Hotfix commits belong **on** `release/X.Y`, then cherry-pick/backport to `dev`/`main`
  so the fix is not lost on the next minor.

### Hotfix checklist (manual for now)

1. `git checkout -b hotfix/… release/1.2` (or branch from `release/1.2`).
2. Fix the bug; bump patch in `Cargo.toml` + `CHANGELOG` (`1.2.0` → `1.2.1`).
3. Merge into `release/1.2`.
4. Tag/publish as needed (`v1.2.1-rc` → forgejorc and/or `v1.2.1` → forgejo).
   Hotfix publish from `release/*` is **not** automated yet.
5. Cherry-pick the fix onto `dev` (and `main` if required).

### What does *not* create `release/X.Y`

| Event | Creates `release/X.Y`? |
| --- | --- |
| Push / merge to `staging` | No (`staging` is only a gate) |
| Push to `dev` / tag `-rc` | No (unstable channel) |
| First stable tag on `main` for that `X.Y` | **Yes** |
| Later stable tags on same `X.Y` (e.g. `1.2.9` from main) | No (branch already exists; left alone) |

## Protecting this directory

A single repository secret (`RUNNER_TOKEN`) is shared across checkout, tag push,
`cargo publish`, and Forgejo releases. That is acceptable because branch
protection on `main` uses **Protected file patterns**:

```text
.gitea/**/*.yml;.forgejo/**/*.yml
```

Those YAML workflows cannot be changed by a direct push even when the user has
write access to the branch (Forgejo Settings → Branches → Protection rules).
Without that control, a contributor could alter a workflow to exfiltrate the
token. Prefer this path protection over splitting many PATs when one-token
rotation is simpler.

## Accepted risk: reusable workflows track the mutable `@main` ref

Date: 2026-09-03

The five reusable workflows in this directory (`check-on-feature-branch.yml`,
`create-tag-on-dev.yml`, `create-tag-on-main.yml`, `publish-on-tag.yml`,
`validate-branch-flow.yml`) call `faicel/central_ci/.forgejo/workflows/*.yml@main`,
a **mutable** ref. The push-triggered jobs pass `RUNNER_TOKEN` to whatever
`@main` contains at run time, so central-repository code executes with that
secret on every run.

The repository owner has explicitly accepted this supply-chain risk for now.
Revisit this decision to pin the `uses:` references to an immutable commit SHA
of `faicel/central_ci` when practical.
