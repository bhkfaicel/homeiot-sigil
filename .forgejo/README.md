# Forgejo Actions (CI)

Security-sensitive checks, tag creation and publication logic live in this
repository. `_rust-crate-checks.yml` is the shared local gate, and
`actions/checkout` is pinned to an immutable commit SHA. This prevents a
mutable transitive workflow from receiving `RUNNER_TOKEN`.

Reusable workflows: Forgejo allows only `inputs` and `outputs` under
`on.workflow_call` (not a callee `secrets` block like GitHub Actions).
Callers must pass repository secrets with `jobs.<id>.secrets: inherit` (or an
explicit map); the callee reads `${{ secrets.RUNNER_TOKEN }}` as usual.

Only the branch-flow validator remains in
[`faicel/central_ci`](https://code.bhk-itsolutions.com/faicel/central_ci); it is
pinned to an immutable revision, receives no secret and invokes no third-party
action.

## Publish flow (happy path)

| Branch | Tag shape | Registry | Forgejo release |
| --- | --- | --- | --- |
| `dev` | `vX.Y.Z-rc` | `forgejorc` (unstable / `homeiot-rc`) | prerelease |
| `staging` | — (merge gate only) | — | — |
| `main` | `vX.Y.Z` | `forgejo` (stable / `homeiot`) | release |

`Cargo.toml` / `CHANGELOG.md` always hold the **stable** base version (e.g. `0.4.0`).
The stable/unstable split is done by **registry**, not by rewriting the crate version.

1. Bump `Cargo.toml` + `CHANGELOG` (required: each version publishes once per registry).
2. Feature branch → checks via `check-on-feature-branch.yml`.
3. Merge to `dev` → `create-tag-on-dev.yml` creates `vX.Y.Z-rc` (fails if the tag already exists).
4. Tag push → `publish-on-tag.yml` publishes to `forgejorc` (client staging can pin this version).
5. Merge `dev` → `staging` → `main` (`staging` does not tag or publish).
6. Push to `main` → `create-tag-on-main.yml` creates `vX.Y.Z` **and** ensures `release/X.Y` exists.
7. Tag push → `publish-on-tag.yml` publishes to `forgejo` (client prod).  
   Note: that workflow sets `enable_tag_check: false` because the tag already exists (it is the trigger); the tag check stays enabled on feature/`dev`/`main` pushes to prevent duplicate releases.

`validate-branch-flow.yml` enforces PR direction via shared `faicel/central_ci` → `validate_flow.yml`:
`* → dev`, `dev → staging`, `staging → main`.

Keep `Cargo.toml` and the latest `CHANGELOG.md` heading in sync (see `scripts/check-version-sync.sh`).

Registries are defined in [`.cargo/config.toml`](../.cargo/config.toml).

`cargo deny` is enabled in local checks and governed by the repository
`deny.toml` policy.

## Maintenance branches (`release/X.Y`)

### Why

`dev` keeps moving (features → next minor). A client or prod may stay on `0.4.0`.
If a bug is found in `0.4.0` while `dev` already has `0.5.0` work, fixing only on `dev`
would force the client to take unwanted features. A **`release/0.4`** line lets you
ship `0.4.1` without `0.5.0`.

```text
main / tag v0.4.0 ──► release/0.4 ──► 0.4.1, 0.4.2   (hotfixes only)
                  └──► dev ─────────► 0.5.0-rc …     (features)
```

### Automation on `main`

When `create-tag-on-main.yml` publishes the first stable `vX.Y.Z` of a minor line, it
creates `release/X.Y` at that commit (via `scripts/release-branch-name.sh`:
`0.4.0` → `release/0.4`).

- If `release/X.Y` **already exists**, CI leaves it unchanged (no force-update).
- Hotfix commits belong **on** `release/X.Y`, then cherry-pick/backport to `dev`/`main`
  so the fix is not lost on the next minor.

### Hotfix checklist (manual for now)

1. `git checkout -b hotfix/… release/0.4` (or branch from `release/0.4`).
2. Fix the bug; bump patch in `Cargo.toml` + `CHANGELOG` (`0.4.0` → `0.4.1`).
3. Merge into `release/0.4`.
4. Tag/publish as needed (`v0.4.1-rc` → forgejorc and/or `v0.4.1` → forgejo).
   Hotfix publish from `release/*` is **not** automated yet.
5. Cherry-pick the fix onto `dev` (and `main` if required).

### What does *not* create `release/X.Y`

| Event | Creates `release/X.Y`? |
| --- | --- |
| Push / merge to `staging` | No (`staging` is only a gate) |
| Push to `dev` / tag `-rc` | No (unstable channel) |
| First stable tag on `main` for that `X.Y` | **Yes** |
| Later stable tags on same `X.Y` (e.g. `0.4.1` from main) | No (branch already exists; left alone) |

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
