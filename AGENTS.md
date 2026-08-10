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
| `scylla-doctor/README.dev.md` | Build, Docker test/lint, packaging, release |
| `scylla-doctor-cluster/README.md` | Cluster tool usage, diff masks, skip/exclude config |

Read the relevant README before changing behavior users see.

## Architecture (scylla-doctor)

```
scylla_doctor.py          CLI entry, Doctor / DoctorEnvironment
collectors.py             ~66 Collector subclasses
analyzers.py              ~62 Analyzer subclasses
collectors_base.py        Collector, CollectorResult, Output
analyzers_base.py         Analyzer, AnalyzerStatus
common.py                 Paths, DictView, config helpers
utils.py                  Executor (shell, files, REST, CQL), Formatter
models/output_entry.py    Structured collector output entries
scylla_doctor.conf        Default INI config shipped with packages
```

**Flow:** `DoctorEnvironment` parses args + INI → `Doctor` auto-discovers classes → collectors run (respecting `depends_on`) → vitals dict → analyzers run → formatted output.

**Auto-registration:** Collectors in `collectors.py` (and `scylla_doctor.py` if any) and analyzers in `analyzers.py` are found via `inspect.getmembers`. Class name = id (e.g. `ClockSourceCollector`). No manual registry.

**Stripped vs full builds:** `make portable` omits `analyzers.py` (collectors-only `.pyz`). `make full` includes analyzers.

## Adding a Collector

1. Subclass `Collector` in `scylla-doctor/collectors.py`.
2. Implement `name` (human label) and `_collect(self, vitals)`.
3. Set `self._data` (dict for analyzers/diffs), `self.status` (`CollectorStatus`), optional `self._message`.
4. Use `self._output.put(...)` for verbose/diagnostic output (`OutputEntryType`: STDOUT, FILE, VALUE, etc.).
5. Optional: `depends_on`, `privileged`, `mask` (keys stripped before cluster diff).
6. **Required:** add tests in `tests/test_collectors.py` (mock `Executor` / filesystem where needed).
7. Document in `scylla-doctor/README.md` collector table if user-facing.

## Adding an Analyzer

1. Subclass `Analyzer` in `scylla-doctor/analyzers.py`.
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
- New modules live under `scylla-doctor/` (flat layout; only `models/` subpackage today).
- Large files use section banners: `# Section name #####...` (see `collectors.py`, `utils.py`, test files).

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
- Dependency skipped → current collector/analyzer SKIPPED (base class); dependency failed → FAILED.
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
- Integration tests use `doctor_factory` / live Scylla in Docker CI.
- Parametrize variants: `@pytest.mark.parametrize`.
- Skip when environment lacks capability: `@pytest.mark.skipif(is_container(), ...)` / root / missing binary.
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
- Comments that restate the code; do comment *why* (skip rules, mask rationale, Scylla quirks).

### Agent checklist

- One collector or analyzer per logical check; minimal diff.
- **Tests included** for every behavior change (see [Testing and lint](#testing-and-lint)).
- Update `scylla-doctor/README.md` tables for new user-visible components.
- Run `make docker-test` (or flake8 + mypy + pytest) before finishing.

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
