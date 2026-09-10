# Scylla Doctor Cluster
Scylla Doctor Cluster analyzes reports gathered from all nodes in Scylla Cluster, looking for failures,
warnings, and inconsistencies among nodes.

## Requirements
* Python 3.8 or above
* scylla-doctor
* python modules (see requirements.txt):
  - PyYAML
  - deepdiff


## Usage
`scylla_doctor_cluster.py path_to_scylla_doctor_outputs`

### Vitals version check
Every `*.vitals.json` file must have been collected by the same Scylla Doctor version as the running cluster tool.
If any file differs, the run exits before analysis and lists **all** mismatched files and their versions.

When the vitals disagree with each other, they have to be collected again with a single Scylla Doctor version:

```
Version mismatch: analyzer: 1.5. Mismatched files: fileA.vitals.json (v1.4), fileB.vitals.json (v1.3). Re-collect the vitals so every node uses the same Scylla Doctor version.
```

When every file agrees and only the cluster tool is out of step, the vitals are fine and the cluster tool has to load the matching Scylla Doctor:

```
Version mismatch: analyzer: 1.5. Mismatched files: fileA.vitals.json (v1.4), fileB.vitals.json (v1.4). All vitals were collected with Scylla Doctor 1.4; run Scylla Doctor Cluster with a matching Scylla Doctor version (--scylla-doctor-path).
```

### Arguments
| Argument                                            | Description                                                                                                                    |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| `path_to_vitals_folder`                             | Directory where vitals from the whole cluster are stored.                                                                      |
| `--config-file FILE`                                | Configuration file name                                                                                                        |
| `--sd-config-file FILE`                             | Scylla Doctor configuration file name                                                                                          |
| `--scylla-doctor-path`                              | Path to scylla_doctor tool contents. It is expected to be the same version that was used to collect vitals from Scylla Cluster |
| `-sov` or `--section-option-value` \<TUPLE STRING\> | Set a configuration file section option value using "SECTION_NAME,OPTION_NAME,[VALUE]" tuple string                            |
| `--output {txt,json}`                               | Output format: 'txt' for a human-readable format, 'json' for a JSON                                                            |

### Configuration file
Configuration file is supposed to be in a Microsoft Windows INI format.

### Scylla Doctor configuration file
See relevant Scylla Doctor documentation.

#### Supported sections

##### General
threshold - numeric parameter, for loose comparison of numeric values in vitals

##### ExcludeFromDiff
Each line contains a name of the Collector to be excluded from a calculation of a difference between node reports.

For instance:

```
[ExcludeFromDiff]
IPRoutesCollector
ScyllaSSTablesCollector
ScyllaClusterSchemaCollector
```

Command line alternative to the above: `-sov ExcludeFromDiff,IPRoutesCollector, -sov ExcludeFromDiff,ScyllaSSTablesCollector, -sov ExcludeFromDiff,ScyllaClusterSchemaCollector, `

The shipped `scylla_doctor_cluster.ini` (loaded with `--config-file scylla_doctor_cluster.ini`) excludes `IPRoutesCollector`, `ScyllaSSTablesCollector`, `IPAddressesCollector`, and `ScyllaLogsCollector` by default — collectors whose `data`/`message` are inherently node- or run-specific. `ScyllaLogsCollector.message` in particular embeds a per-run timestamped log file path, which always differs across nodes and runs.

##### SkipTest
Each line contains a name of an Analyzer that is going to be skipped.

For instance:

```
[SkipTest]
CPUScalingAnalyzer
```
Command line alternative: `-sov SkipTest,CPUScalingAnalyzer,`

##### \<Analyzer Name\>
Provide per-Analyzer/Collector options (see Scylla Doctor README.md for more information on per-Analyzer/Collector options).
Value defined in this section is going to be forwarded to Scylla Doctor
via `-sov <Analyzer name>,option,value`

##### \<Collector Name\>
Provide per-Collector options similarly to per-Analyzer options above.

###### mask
Each Collector configuration section can have this additional field. 
Mask is a list of definitions that specify what `data` elements should be
excluded from the diff calculation of a specific Collector.

Mask can include a data key to be filtered or a tuple that represents
a "path" to a key to be filtered when data is a nested dictionary.

For example:

If `data` has `data['k1']['k2']` and `data['k3']` to filter both these values
a mask can be as follows:

`mask = [('k1', 'k2'), 'k3']`

Command line alternative for the mask above for a `Collector1` is: `-sov "Collector1,mask,[('k1', 'k2'), 'k3']"`

If a mask key value equals '*' it matches any key.
Note that `[('*','*','*')]` mask is not equal to `[('*', '*')]` or to `['*']`.

`[('*','*','*')]` is going to delete all keys of a 3-levels deep nested dictionaries.

For example if
```
data = {
        "k0" : { "k2" : "6" },
        "k1" : { "k2" : {"k2" : "3",
                         "k4" : "4"},
                 "k3":  {"k2": "3",
                         "k3": "4"}
                 },
        "k3" : {},
        "k2" : "4",
        }
```
Filtering with `[('*','*','*')]` will result in
```
data = {
        "k0": { "k2": "6" },
        "k1": { "k2": {},
                "k3": {}
              },
        "k3": {},
        "k2": "4"
}
```
