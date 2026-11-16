# AGENTS.md

Guide for coding agents working in this repository.

## Overview

Scylla Doctor is a ScyllaDB node health and troubleshooting tool. It **collects vitals** from a host (or from a saved JSON file) and **analyzes** them against Scylla best practices.

| Component | Path | Role |
|-----------|------|------|
| **scylla-doctor** | `scylla-doctor/` | Per-node collectors + analyzers |
| **scylla-doctor-cluster** | `scylla-doctor-cluster/` | Cross-node diff of vitals from a cluster |

License: AGPL-3.0 (`LICENSE`).

## Documentation map

| Doc | Contents |
|-----|----------|
| `scylla-doctor/README.md` | User-facing usage, full collector/analyzer reference, INI config |
| `scylla-doctor/README.dev.md` | Build, Docker test/lint, packaging, release, PR review bot labels |
| `scylla-doctor-cluster/README.md` | Cluster tool usage, diff masks, skip/exclude config |

Read the relevant README before changing behavior users see.

## Architecture (scylla-doctor)

```
scylla_doctor.py          CLI entry, Doctor / DoctorEnvironment, class discovery
collectors/<category>.py  Collector subclasses, one module per category
analyzers/<category>.py   Analyzer subclasses, same category names
analyzers/helpers.py      helpers several analyzers share (compare_versions, get_url_content, ...)
collectors_base.py        Collector, CollectorResult, Output, REST API collector bases
analyzers_base.py         Analyzer, AnalyzerStatus
common.py                 Paths, DictView, config helpers
utils.py                  Executor (shell, files, REST, CQL), Formatter
models/output_entry.py    Structured collector output entries
scylla_doctor.conf        Default INI config shipped with packages
```

**Flow:** `DoctorEnvironment` parses args + INI → `Doctor` auto-discovers classes → collectors run (respecting `depends_on`) → vitals dict → analyzers run → formatted output.

**Auto-registration:** `_classes_in_package()` in `scylla_doctor.py` walks the `collectors` and `analyzers` packages and takes every concrete `Collector` / `Analyzer` subclass defined in any module under them, sorted by class name (that order drives run order and reports). Class name = id (e.g. `ClockSourceCollector`). No manual registry, nothing to import or list: a new class in a category module is enough.

**Stripped vs full builds:** `make portable` omits the `analyzers/` package (collectors-only `.pyz`). `make full` includes it.

**Categories** (same module names under `collectors/` and `analyzers/`; an analyzer sits with the collector it checks, unless the subject of the check belongs elsewhere):

| Category | Covers |
|----------|--------|
| `hardware` | CPU, memory, PCI and interrupt facts about the machine |
| `cloud` | cloud provider, instance type, platform detection, maintenance events |
| `storage` | data disks, RAID, NVMe devices, filesystems, sstables on disk |
| `operating_system` | kernel settings, resource limits, system daemons, swap, coredumps |
| `time_sync` | NTP and chrony daemons and their sync status |
| `tuning` | what `scylla_setup` / `perftune.py` write: `/etc/scylla.d`, cpuset, IRQ and NIC placement |
| `network` | NICs, addresses, routes, firewall, sockets, seed reachability |
| `clients` | connected drivers and their workload settings |
| `config` | operator-edited configuration and its live counterpart: `scylla.yaml`, sysconfig, `system.config` |
| `install` | what is installed and running: Scylla version, binary, services, paths, Scylla Doctor version |
| `schema` | data model and schema agreement |
| `topology` | membership, gossip, Raft, tablets |
| `security` | who can log in and with what rights |
| `logs` | journal and kernel ring buffer dumps (collectors only) |

## Adding a Collector

1. Subclass `Collector` in `scylla-doctor/collectors/<category>.py`, placed in alphabetical order by class name (a readability convention; discovery sorts by class name anyway). Pick the category from the table above; a new category is a new module, nothing else.
2. Implement `name` (human label) and `_collect(self, vitals)`.
3. Set `self._data` (dict for analyzers/diffs), `self.status` (`CollectorStatus`), optional `self._message`.
4. Use `self._output.put(...)` for verbose/diagnostic output (`OutputEntryType`: STDOUT, FILE, VALUE, etc.).
5. Optional: `depends_on`, `privileged`, `skip_in_container` (reason to skip inside containers), `mask` (keys
   stripped before cluster diff).
6. **Required:** add tests in `tests/test_collectors.py` (mock `Executor` / filesystem where needed).
7. Document in `scylla-doctor/README.md` collector table if user-facing.

## Adding an Analyzer

1. Subclass `Analyzer` in `scylla-doctor/analyzers/<category>.py`, alphabetical by class name, normally in the same category as the collector it checks (`ClockSourceAnalyzer` in `analyzers/operating_system.py` next to `ClockSourceCollector` in `collectors/operating_system.py`).
2. Implement `name`, `depends_on` (collector id set), `_analyze(self, vitals)`.
3. Set `self.status` (`PASSED`, `SKIPPED`, `WARNING`, `FAILED`) and `self.message`.
4. Docstring on `_analyze` appears in `--help` epilog.
5. **Required:** add tests in `tests/test_analyzers.py` using `check_analyzer()` / synthetic `CollectorResult` vitals.
6. Document in `scylla-doctor/README.md` analyzer table.

**Status rules:** Never bool-cast `AnalyzerStatus`. Use explicit comparisons. Combine with `AnalyzerStatus.combine()`.

## Configuration

INI format (`configparser`, `BasicInterpolation`). Sections:

- `DefaultPaths` — Scylla install paths
- `CQL` — credentials for schema collectors
- `[CollectorName]` / `[AnalyzerName]` — `run = no` to skip; analyzer/collector-specific params

CLI overrides: `-sov SECTION,OPTION,VALUE` (e.g. `-sov SwapAnalyzer,run,no`).

Cluster tool forwards per-analyzer/collector options to scylla-doctor via `-sov`.

## Vitals

- Save: `--save-vitals [file.json]`
- Load: `--load-vitals [file.json]` (skips live collection)
- Version check on load: compares vitals version to tool version; exits on mismatch; override with `--ignore-vitals-version`
- `--version` prints tool version; `--vitals-version [file]` prints version from a vitals file

## Testing and lint

**Every feature change must include tests.** A feature is not done without them.

| Change | Required tests |
|--------|----------------|
| New or modified Collector | `tests/test_collectors.py` — cover PASSED, FAILED, and SKIPPED paths where applicable |
| New or modified Analyzer | `tests/test_analyzers.py` — cover each status outcome and config branches |
| New config option / CLI flag | Tests proving the option affects behavior |
| `utils.py`, `common.py`, CLI wiring | `tests/test_utils.py`, `tests/test_collector_api.py`, `tests/test_analyzer_api.py`, or smoke tests as appropriate |
| `scylla-doctor-cluster` behavior | Add or extend tests (e.g. `tests/test_cluster.py` when present); at minimum unit-test diff/mask/config logic |

Do not merge behavior-only changes with no test coverage. Bug fixes include a regression test.

All commands from `scylla-doctor/` unless noted.

```bash
make docker-test      # flake8 + mypy + pytest + coverage (preferred)
make docker-enter     # shell in test container (Scylla running)
make docker-lint      # flake8 + mypy only
make container-single-test TEST=tests/test_foo.py::test_bar
```

Local (needs Scylla on 9042 for integration tests):

```bash
pip install -r tests/requirements.txt
make version          # writes ./version from dist/common/{major,minor}
python3 -m flake8
python3 -m mypy .
python3 -m pytest -vv
```

**Conventions:**

- `tests/conftest.py` — `doctor_factory` fixture for isolated collector/analyzer runs
- `tests/helpers.py` — shared assertions and mocks
- Max line length 120 (`.flake8`)
- mypy pinned `<1.19.0` in test requirements
- Some tests skip in containers (`is_container()` in `test_collectors.py`)

CI (`.github/workflows/scylla-doctor-test.yaml`): Scylla container, lint, pytest with coverage. Runs on PRs touching `scylla-doctor/**`.

## Packaging and version

Version: `scylla-doctor/dist/common/major` + `minor` → `make version` → `./version` file.

| Target | Output |
|--------|--------|
| `make portable` | collectors-only `scylla_doctor.pyz` |
| `make full` | full `scylla_doctor.pyz` |
| `make stripped_deb/rpm/tgz` | OS packages (stripped) |
| `make full_tgz` | tarball with full build |

Release (see `README.dev.md`): bump `dist/common/{major,minor}` on master, tag `vX.Y`, CI publishes artifacts.
`CHANGELOG` and the version files change only in that release step, never in a feature PR: a PR describes its
user-visible change in its description, and the release collects them.

Cluster packaging: `scylla-doctor-cluster/Makefile` bundles scylla-doctor via `copy_all` into `scylla_doctor_cluster.pyz`.

## scylla-doctor-cluster

Single main file: `scylla_doctor_cluster.py`. Depends on scylla-doctor (same version as vitals), PyYAML, deepdiff.

- Input: directory of per-node vitals JSON from `scylla-doctor --save-vitals`
- Compares collector `data` across nodes with `DeepDiff`
- Config sections: `General` (threshold), `ExcludeFromDiff`, `SkipTest`, per-collector `mask`
- Output: `--output txt|json`

No dedicated cluster test suite yet — **add one** (`scylla-doctor-cluster/tests/` or `scylla-doctor/tests/test_cluster.py`) when implementing cluster features. Do not ship cluster logic without tests.

## Style guide

Match surrounding code in the file you edit. When in doubt, copy the nearest existing Collector/Analyzer.

### Files and headers

- Every `.py` file starts with the ScyllaDB AGPL copyright block (copy from any existing module).
- Entry script `scylla_doctor.py` also has `# -*- coding: utf-8 -*-`.
- Collectors and analyzers live in `collectors/<category>.py` and `analyzers/<category>.py`, one module per category (table under Architecture). Every other module stays flat under `scylla-doctor/` (`models/` is the only other subpackage).
- Large files use section banners: `# Section name #####...` (see `utils.py`, test files).

### Imports

```python
import os
import json                          # stdlib, grouped

from typing import Dict, Set, Optional

from common import DictView
from collectors_base import Collector, CollectorStatus
from models.output_entry import OutputEntryType, Level
from utils import Executor
```

- Stdlib → blank line → typing → blank line → local imports.
- Prefer explicit imports over `import *`.
- Keep imports at top; no lazy imports unless matching an existing pattern (e.g. optional `analyzers` in stripped builds).

### Naming

| Kind | Convention | Example |
|------|------------|---------|
| Collector/Analyzer class | PascalCase + suffix | `ClockSourceCollector`, `RAMAnalyzer` |
| Class id / config section | Same as class name | `[ClockSourceAnalyzer]` |
| `name` property | Short human label | `"Clock source setup collection"` |
| Dependency refs | Private `@property` | `__collector`, `__collector_cql` → returns `"ClockSourceCollector"` |
| Paths / constants in class | Private `@property` or module const | `__clocksource_file`, `ENCODING = "UTF-8"` |
| Vitals `data` keys | snake_case strings | `'clocksource'`, `'scaling_governor'` |
| Test functions | `test_<ClassName>` or `test_<ClassName>_<case>` | `test_ClockSourceAnalyzer` |
| Exceptions | PascalCase + `Exception` | `CqlFailedException`, `AbortedException` |

Do not introduce a separate string id — `id` comes from `__class__.__name__`.

### Collector implementation

```python
class ClockSourceCollector(Collector):
    @property
    def name(self) -> str:
        return "Clock source setup collection"

    @property
    def __clocksource_file(self) -> str:
        return "/sys/devices/system/clocksource/clocksource0/current_clocksource"

    @property
    def depends_on(self) -> Set[str]:
        return {"OtherCollector"}          # only if needed

    def _collect(self, vitals: DictView) -> None:
        if not os.path.isfile(self.__clocksource_file):
            self.status = CollectorStatus.FAILED
            self._message = f"Clock source cannot be determined, check {self.__clocksource_file}"
            return

        self._data = {'clocksource': Executor.read_file_content(self.__clocksource_file)[0].strip()}
        self._output.put(OutputEntryType.FILE, self.__clocksource_file,
                         [f"{self._data['clocksource']}\n"], level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED
```

Rules:

- Implement `_collect`, never override public `collect`.
- Set `self.status` on every exit path; use early `return` after FAILED.
- Populate `self._data` with stable keys analyzers and cluster diff rely on.
- Put raw command/file/API output in `self._output.put(...)` at `Level.VERBOSE` (or `DETAILED` when appropriate).
- Read config via `self.config.get('key', default)`; paths via `self._paths['scylla_directory_configs']`.
- Shell/files/network/CQL: use `Executor` (`run_command`, `read_file_content`, `get_url_content`, `read_cql_table`) — not ad-hoc `subprocess`.
- REST endpoints: subclass `ScyllaRestApiAwareCollector`; unsupported API → `CollectorStatus.SKIPPED` via base helpers.
- `privileged = True` only when root is required; base class handles skip.
- `skip_in_container` returns a reason (`Optional[str]`, `None` = runs) when the collector reads host state a
  container usually cannot see (host services, the journal, the host disk inventory); the base class skips it
  inside containers with "Not available for containers: <reason>". Do not use it for operations a container may
  refuse (`dmesg`, `iptables`): run them with `check=False` and skip only when
  `running_in_container()` (from `utils`) and the call was refused, with the tool's error in the message.
- Tools: check binaries with `self._require_tools('a', 'b')`, which sets SKIPPED `'<tool>' not installed`. A bare
  command that turns out to be missing at run time is skipped the same way by the base class. A missing tool is
  never FAILED.
- `mask`: return keys/paths to strip before cluster diff; document why in a docstring (see `ClientConnectionCollector`).
- Reuse generic bases (e.g. `ScyllaSimplePerTableRestApiCollector[T]`) when the REST pattern already exists.

### Analyzer implementation

```python
class ClockSourceAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Clock source setup analysis"

    @property
    def __collector(self) -> str:
        return "ClockSourceCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that clocksource is set up to a recommended value.
        """
        clocksource = vitals[self.__collector].data['clocksource']
        ...
```

Rules:

- Implement `_analyze`, never override public `analyze`.
- Docstring on `_analyze` is user-facing (`--help` epilog) — one clear sentence.
- Always set both `self.status` and `self.message` before returning.
- `PASSED` / `WARNING` / `FAILED` / `SKIPPED`: use `SKIPPED` when the check does not apply (wrong arch, feature absent, config disabled).
- Never `if analyzer.status:` — `AnalyzerStatus` forbids implicit bool (explicit compare only).
- Comma-separated config lists: `self._parse_comma_separated_config('skip_files')`.
- Numeric config defaults: inline with unit comment (`4194304  # 4 gb`).
- User messages: full sentences; name the failing value or threshold.

### Status and errors

- Collectors: `CollectorStatus.PASSED | FAILED | SKIPPED`.
- Analyzers: `AnalyzerStatus.PASSED | SKIPPED | WARNING | FAILED`; combine lists with `AnalyzerStatus.combine()`.
- Dependency skipped → current collector/analyzer SKIPPED (base class) and its message repeats the dependency's
  reason; dependency failed → FAILED.
- Catch domain errors in `_collect` (e.g. `CqlFailedException`), set FAILED + message; let unexpected errors propagate (base wraps them).
- Config parse errors: raise with `from cpe` chaining (`read_config_file` pattern).

### Types and lint

- Type hints on properties and method signatures; return types on `@property`.
- Max line length **120** (`.flake8`). Break lines or append `# noqa: E501` when a long string/dict is clearer on one line.
- mypy runs in CI; use `# type: ignore[code]` sparingly, same style as existing code.
- Python **3.8+**: no `functools.cache` (use `memoize` in `utils.py`); prefer `dataclasses` and `enum` as elsewhere.

### Tests

**Required for every feature.** Match existing files; do not land collectors, analyzers, or behavior changes without tests.

- Add collector tests to `tests/test_collectors.py`, analyzer tests to `tests/test_analyzers.py`.
- Cover the meaningful branches: success, failure, skip, and config overrides.
- Analyzers: prefer table-driven `check_analyzer(analyzer, collector_name, [(input, AnalyzerResult(...)), ...])`.
- Assert with `assert_analyzer_result(analyzer, status, message_substring)`.
- Mock external I/O: `unittest.mock.patch` on `Executor` methods; use `tests.helpers` stubs (`DummyCollector`, etc.).
- Patch a name where the module under test looks it up, e.g. `patch('collectors.time_sync.ServiceManager')`; objects shared through `utils` or the stdlib (`Executor`, `shutil.which`) are patched where they live.
- Integration tests use `doctor_factory` / live Scylla in Docker CI.
- Parametrize variants: `@pytest.mark.parametrize`.
- Skip when environment lacks capability: `@pytest.mark.skipif(is_container(), ...)` / root / missing binary.
- Container behaviour: patch `running_in_container` where the code under test looks it up
  (`collectors.<category>.`, `collectors_base.` or `utils.running_in_container`) rather than relying on the test host.
- Group related tests under banner comments: `# FooCollector unit tests #####...`.

### scylla-doctor-cluster

- Same copyright header and import style.
- Keep logic in `scylla_doctor_cluster.py`; config parsing in `Configuration` class.
- Match INI section naming documented in `scylla-doctor-cluster/README.md`.

### What to avoid

- One-off helper functions for a single call site.
- New registries or manual lists — discovery is automatic via subclassing.
- Hardcoded secrets, real cluster vitals, or customer hostnames in tests/commits.
- Changing vitals JSON shape without version bump consideration.
- Editing `CHANGELOG` or `dist/common/{major,minor}` in a feature PR; both change only at release time (see
  [Packaging and version](#packaging-and-version)).
- Comments that restate the code; do comment *why* (skip rules, mask rationale, Scylla quirks).

### Agent checklist

- One collector or analyzer per logical check; minimal diff.
- **Tests included** for every behavior change (see [Testing and lint](#testing-and-lint)).
- Update `scylla-doctor/README.md` tables for new user-visible components.
- Run `make docker-test` (or flake8 + mypy + pytest) before finishing.

<!-- pr-review-bots:start -->
## PR review automation

Every push to a non-draft PR from this repo runs two bots:

1. **Review** (`.github/workflows/pr-code-review.yml`): waits 2 minutes (a newer push cancels the run), then
   runs the `pr-code-reviewer` skill. It posts one review with four passes (reviewer, org reviewer,
   over-engineering, security), each finding tagged 🔴 Blocking, 🟠 Important, 🟡 Minor, 🔵 Nit/Simplify,
   ❓ Question or 💡 Praise.
2. **Resolver** (`.github/workflows/pr-comment-resolver.yml`): runs the `prr` skill to fix open review
   threads and merge conflicts, committing and pushing up to `MAX_ROUNDS` (3) rounds. Each push is reviewed
   again, so the loop is review → fix → review until nothing is left to fix. A loop guard stops both bots after
   `MAX_BOT_RUNS` (5) runs since the last human commit, or after N runs when a `review_max_runs:N` (or, on
   the first push, `review_max_initial_runs:N`) label sets a larger N (99 at most).

Drafts, fork PRs and closed PRs are skipped; Dependabot PRs get only the resolver. Marking a PR as draft
also stops a running resolver after its current round. Helper logic and its tests:
`.github/scripts/pr-resolver-tools.sh`, `.github/scripts/test-pr-resolver-tools.sh`. The bots need the
`ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` repository secret, and `PR_RESOLVER_TOKEN` when branch rules
keep `github-actions[bot]` from pushing to PR branches.

**Labels** limit both bots, or extend the loop for a large PR. Each gate reads them when it runs; adding or
removing one starts nothing. A label must exist before it can be added (`gh label create <name>`).

| Label | Effect |
|-------|--------|
| `review_stop` | No review and no fixes while set; a running resolver stops after its current round |
| `review_skip_on_open` | No review and no fixes for the PR's first push |
| `review_only` | Review only: every push is still reviewed, but the resolver fixes and resolves nothing, whatever other labels say. It overrides `review_max_*runs`, its loop guard included (the resolver's log reports it as a `review_max_*runs` limit). It applies from the next resolver run; to stop one already running, use `review_stop`. Remove it to have fixes from the next push on |
| `review_max_runs:N` | At most N fix rounds after each push; `0` or the bare label leaves the comments to people. N above 5 raises the loop guard to N |
| `review_max_initial_runs:N` | Same, for the first push only |
| `review_min_severity:<level>` | Resolver fixes only `blocking`, `important`, `minor` or `nit` (default) and up; ❓ and 💡 are always left to people |

A push is a person's: the resolver's own pushes, and pushes of commits authored by Claude Code
(`noreply@anthropic.com`), are fix rounds of the push before them. A change of the PR's base branch is not a
push and does not reset the rounds used. Findings the resolver leaves stay open; a reply on one from someone
with write access has it act on that thread.

**Advisory: pick labels to fit the PR.** No label drops a review pass; the labels limit how many rounds of
fixes the resolver commits on top of your work.

| PR | Suggested labels |
|----|------------------|
| Small or trivial (typo, docs, one-line fix) | `review_max_runs:1` |
| Normal feature or bug fix | No labels, or `review_min_severity:important` to skip nits |
| You want to address the findings yourself | `review_only` |
| Large | `review_max_runs:8` (up to 99) to go past the default 5 runs. Pushing a commit of your own also starts another round of runs |
| Work in progress | Keep it as draft, or set `review_stop` after the first review |

Agents working on a PR: the resolver's commits land on the PR branch, so `git pull` before pushing. Don't
push fixes for the same threads the resolver is working on; set `review_stop` first.
<!-- pr-review-bots:end -->

## Key CLI flags (quick ref)

| Flag | Purpose |
|------|---------|
| `--output full\|short\|json` | Report format |
| `--print-filter REGEX` | Filter printed collectors/analyzers |
| `-d` / `-v` | Detailed / verbose |
| `-st TEST` | Skip named test |
| `-aofe` | Abort on first error |
| `-cf FILE` | Config file |

Full flag and per-component parameter docs: `scylla-doctor/README.md`.
