# How to run tests (and linter) in Docker
```
make docker-test
```

Client-to-node SSL (orchestrated by `ci/enable_client_node_ssl.py`; verifies `cqlsh --ssl` against a node with `client_encryption_options.enabled`):
```
make container-test SSL=1
```

CI runs the SSL leg on every push to master; on a PR, add the `ci:client-ssl` label and then push (or close/reopen the PR) to run it, since label events alone do not trigger the workflow.

Or, if you want to play inside the container:
```
make docker-enter
```

And there, for example:
```
python3 -m pyte
```

# How to prepare portable version manually
```
make portable
```

# How to build a new DEB/RPM/TGZ package with a stripped (Collectors only) artifact
```
make stripped_deb
make stripped_rpm
make stripped_tgz
```

# How to build full (Collectors and Analyzers) relocatable version
```
make full
```

# How to build full (Collectors and Analyzers) relocatable version and package it into a tarball
```
make full_tgz
```

# How to clean
```
make clean
make clean_rpm
make clean_deb
make clean_tgz
```

# How publish a new release
1. Update version files `dist/common/{major,minor}` in the `master` branch.
2. Create a new release with a tag according to values set in (1), e.g. `scylla-doctor-v4.2`.
3. The moment a new release is published new versioned artifacts are going to be uploaded
   to ScyllaDB's S3 bucket and on downloads.scylladb.com. The publish workflows verify
   that the release tag matches `dist/common/{major,minor}` before publishing anything.



# How to limit the PR review bots
Every push to a non-draft PR gets a Claude review (`.github/workflows/pr-code-review.yml`), then the comment resolver (`.github/workflows/pr-comment-resolver.yml`) commits fixes for the open review threads. These PR labels limit both. Each gate reads them when it runs; adding or removing one starts nothing.

| Label | Effect |
|-------|--------|
| `review_stop` | No review and no fixes while it is set; a resolver already running stops after its current round, as it does when you mark the PR as draft. Add it after the first review to keep the bots off your later pushes |
| `review_skip_on_open` | No review and no fixes for the PR's first push |
| `review_max_runs:N` | After each push, at most N rounds of fixes, each reviewed again; `0` or the bare label leaves the review comments to you. N above 5 also raises the loop guard (`MAX_BOT_RUNS`, 5 runs since your last push) to N for that push, 99 at most |
| `review_max_initial_runs:N` | The same for the first push, instead of `review_max_runs` |
| `review_min_severity:<level>` | The resolver fixes only review findings at `blocking` (🔴), `important` (🟠), `minor` (🟡) or `nit` (🔵, the default) and up; the rest is left to you |

A push is yours: the resolver's own pushes are fix rounds of the push before them. Pushes of commits authored by Claude Code (`noreply@anthropic.com`), for example from Claude Code on the web, also count as fix rounds, not as new pushes, so they use up the rounds of your last push of your own commits. On a PR with no commits of your own at all, the first push counts as yours and every later push as one of its rounds. A change of the PR's base branch is not a push either: it does not reset the rounds used, so with none left the resolver skips even a merge conflict the change brings, and leaves it to you. For example, `review_max_runs:0` with `review_max_initial_runs:3` keeps up to three rounds of fixes for the first push and only reviews your follow-up pushes. A label must exist before it can be added, e.g. `gh label create review_max_runs:0`.

By default the resolver works on every review finding except ❓ Question and 💡 Praise, which ask for no change; 🔵 covers both Nit and Simplify findings, and 🔴 also Critical/High security ones. `review_min_severity:important` keeps it to 🔴 and 🟠, for example. Findings it leaves to you stay open; a reply on one from someone with write access has it act on that thread. Other bots' comments and comments from people with write access are always worked on.
