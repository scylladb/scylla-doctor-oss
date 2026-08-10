# Scylla Doctor
Scylla Doctor is an advising and troubleshooting tool which determines within seconds the node status regarding to system requirements, configurations and tuning.

## Usage
Scylla Doctor requires Scylla distribution package to be installed.

Scylla Doctor can be executed the following way depending on the installation type:

| Installation type      | Executable name   |
|------------------------|-------------------|
| Sources                | scylla_doctor.py  |
| Self-contained archive | scylla_doctor.pyz |
| OS package             | scylla-doctor     |

#### How to run it
* `sudo /opt/scylladb/python3/bin/python3 scylla_doctor.py` to run a quick check locally
* use `--save-vitals [filename.json]` to save full vitals for further analysis
* use `--load-vitals [/path/to/vitals.json]` to analyze data from vitals file (instead of local environment).

### Arguments
See `scylla_doctor.py --help` for details

## Full list of available Collectors and Analyzers
See `scylla_doctor.py --help` for details

## Collectors and Analyzers reference

### Collectors

| Collector                                   | Data collected                                                                                                                                                          |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PathsCollector`                            | Configured Scylla directory paths                                                                                                                                       |
| `ClockSourceCollector`                      | Current clock source from `/sys/devices/system/clocksource/clocksource0/current_clocksource`                                                                            |
| `CPUSpecificationsCollector`                | CPU flags and logical core count via `lscpu` and `/proc/cpuinfo`                                                                                                        |
| `CPUScalingCollector`                       | CPU scaling governor value; status of CPU scaling services (cpupower, scylla-cpupower, etc.)                                                                            |
| `CPUSetCollector`                           | CPU mask from `cpuset.conf`; CPU mask from `perftune.yaml`; their bitwise intersection                                                                                  |
| `CoredumpCollector`                         | Coredump sysctl config files; status of `var-lib-systemd-coredump.mount` service                                                                                        |
| `ClientConnectionCollector`                 | Per-client-IP rows from `system.clients`: driver name, driver version, port                                                                                             |
| `FirewallRulesCollector`                    | Output of `iptables -L -v`                                                                                                                                              |
| `MaintenanceEventsCollector`                | Scheduled maintenance events from cloud provider metadata API                                                                                                           |
| `InfrastructureProviderCollector`           | Cloud provider name, instance type, CPU platform (from cloud metadata API)                                                                                              |
| `IPAddressesCollector`                      | Output of `ip addr show` for every NIC                                                                                                                                  |
| `KernelRingBufferCollector`                 | Output of `dmesg -T`                                                                                                                                                    |
| `NICsCollector`                             | NIC names, driver, and link speed via `ethtool`                                                                                                                         |
| `NodePlatformCollector`                     | Node platform type: `CONTAINER`, `CLOUD`, `VM`, or `BAREMETAL`                                                                                                          |
| `NTPStatusCollector`                        | NTP enabled and clock-synchronized flags from `timedatectl show`                                                                                                        |
| `NTPServicesCollector`                      | Active status of NTP-related services (systemd-timesyncd, chronyd, ntpd, etc.)                                                                                          |
| `ChronyStatusCollector`                     | Chrony synchronization state from `chronyc tracking` leap status                                                                                                      |
| `ChronyServicesCollector`                   | Active status of chrony-related services (`chronyd`, `chrony`)                                                                                                          |
| `ComputerArchitectureCollector`             | CPU architecture and kernel version from `uname --all`                                                                                                                  |
| `OSCollector`                               | OS distribution name and version from `/etc/os-release`                                                                                                                 |
| `PerftuneSystemConfigurationCollector`      | `perftune.py --dry-run` recommendations (file values and sysctl params) and their actual current values                                                                 |
| `PerftuneYamlDefaultCollector`              | Default `perftune.yaml` content and CPU mask as generated by `perftune.py --dump-options-file`                                                                          |
| `RAIDSetupCollector`                        | Content of `/proc/mdstat`                                                                                                                                               |
| `NVMeDevicesCollector`                      | NVMe namespace devices and whether each is mounted or used by an active software RAID (AWS root EBS volume excluded)                                                     |
| `RAMCollector`                              | Total RAM from `free` and `/proc/meminfo`                                                                                                                               |
| `RsyslogCollector`                          | Content of `/etc/rsyslog.d/scylla.conf`                                                                                                                                 |
| `SysctlCollector`                           | Values of `fs.aio-max-nr`, `fs.file-max`, `fs.nr_open`                                                                                                                  |
| `IPRoutesCollector`                         | `ip route show match` output for each Scylla address (listen, broadcast, rpc, api)                                                                                      |
| `CqlshCollector`                            | CQL connectivity check via `cqlsh HELP`                                                                                                                                 |
| `ScyllaClusterSchemaDescriptionCollector`   | Full schema text from `DESC SCHEMA`                                                                                                                                     |
| `ScyllaClusterSchemaCollector`              | Schema version-to-node-IP mapping from `/storage_proxy/schema_versions` REST API                                                                                        |
| `RaftTopologyRPCStatusCollector`            | Ongoing Raft topology RPC status from `/storage_service/raft_topology/cmd_rpc_status` REST API                                                                          |
| `ScyllaClusterStatusCollector`              | Sets of up/down/joining/leaving/moving node IPs from gossiper REST API                                                                                                  |
| `ScyllaClusterSystemKeyspacesCollector`     | Rows of `system_schema.keyspaces`: keyspace names and replication settings                                                                                              |
| `ScyllaClusterTablesDescriptionCollector`   | Rows of `system_schema.tables` and `system_schema.views` (materialized views, secondary indexes; CDC log tables included as regular tables): names, compaction, compression, and other schema metadata. Each row is tagged with `table_kind` (`table`/`view`) |
| `ScyllaConfigurationFileCollector`          | Parsed `scylla.yaml` with default substitution and DNS resolution for address fields                                                                                    |
| `ScyllaConfigurationFileNoParsingCollector` | Raw (unparsed) `scylla.yaml` values as strings                                                                                                                          |
| `ScyllaExtraConfigurationFilesCollector`    | All files under `scylla_directory_configs`: `io.conf`, `cpuset.conf`, `perftune.yaml`, `io_properties.yaml`, etc.                                                       |
| `ScyllaBinaryCollector`                     | Path to the `scylla` binary                                                                                                                                             |
| `ScyllaLimitNOFILECollector`                | `LimitNOFILE` value from `scylla-server.service` environment                                                                                                            |
| `ScyllaLogsCollector`                       | Scylla logs from `journalctl --unit=scylla-server` (saved to a compressed file)                                                                                         |
| `ScyllaManagerAgentLogsCollector`           | Scylla Manager Agent logs from `journalctl --unit=scylla-manager-agent` (saved to a compressed file; skipped when the agent is not installed)                            |
| `ScyllaServicesCollector`                   | Active and autostart status of Scylla-related services                                                                                                                  |
| `ScyllaSeedsCollector`                      | Seed addresses from `scylla.yaml`; TCP connectivity result to each seed                                                                                                 |
| `ScyllaSSTablesCollector`                   | List of all SSTable files under `scylla_directory_var/data`                                                                                                             |
| `ScyllaSystemConfigurationFilesCollector`   | Parsed contents of `scylla-server`, `scylla-jmx`, and `scylla-housekeeping` sysconfig files                                                                             |
| `GossipInfoCollector`                       | Per-host gossip application state (HOST_ID, TOKENS, SCHEMA, DC, RACK, STATUS, SUPPORTED_FEATURES, CDC_GENERATION_ID, etc.) from `/failure_detector/endpoints/` REST API |
| `TokenMetadataHostsMappingCollector`        | IP-to-host-UUID mapping from `/storage_service/host_id` REST API                                                                                                        |
| `RaftGroup0Collector`                       | Raft Group0 ID, upgrade state, and member host IDs from `system.scylla_local` and `system.raft_state`                                                                   |
| `SystemPeersLocalCollector`                 | Per-host info (host_id, DC, rack, tokens, schema_version, etc.) from `system.peers` and `system.local`                                                                  |
| `SystemClusterStatusCollector`              | Per-host cluster status from `system.cluster_status`                                                                                                                    |
| `SystemTopologyCollector`                   | Rows of `system.topology` with Raft topology upgrade state; detects whether Consistent Topology is supported                                                            |
| `SystemTabletsCollector`                    | Tablet ownership from `system.tablets` (nested `data.tables`; ownership columns only; masked from cluster drift)                                                        |
| `LargePartitionsCellsRowsCollector`         | Rows from `system.large_partitions`, `system.large_cells`, and `system.large_rows`                                                                                      |
| `RolePermissionsCollector`                  | Rows from `system.role_permissions`                                                                                                                                     |
| `SystemConfigCollector`                     | All Scylla runtime parameters from `system.config`: name, value, source, and type                                                                                       |
| `ScyllaVersionCollector`                    | Scylla version string, edition (oss/enterprise/development), installed Scylla packages                                                                                  |
| `SELinuxCollector`                          | Content of `/etc/selinux/config`                                                                                                                                        |
| `ServiceManagerCollector`                   | Service manager type (e.g. systemd)                                                                                                                                     |
| `StorageConfigurationCollector`             | For each Scylla data directory: underlying devices (NVMe/non-NVMe), filesystem type, mount point, mount options, total and free storage size                            |
| `SwapCollector`                             | Total swap size from `/proc/swaps`                                                                                                                                      |
| `TCPConnectionsCollector`                   | All TCP connections from `ss --all --tcp`                                                                                                                               |
| `SDVersionCollector`                        | Scylla Doctor version from the version file                                                                                                                             |
| `HypervisorTypeCollector`                   | Hypervisor type from `systemd-detect-virt` (e.g. `kvm`, `xen`, `none`)                                                                                                  |
| `ProcInterruptsCollector`                   | Content of `/proc/interrupts`                                                                                                                                           |
| `LSPCICollector`                            | Output of `lspci -vvv`                                                                                                                                                  |
| `SeastarCPUMapCollector`                    | Output of `seastar-cpu-map.sh -n scylla`                                                                                                                                |
| `NodetoolCFStatsCollector`                  | Output of `nodetool cfstats`                                                                                                                                            |
| `ScyllaTablesCompressionInfoCollector`      | Per-table compression ratio from `/column_family/metrics/compression_ratio` REST API                                                                                    |
| `ScyllaTablesUsedDiskCollector`             | Per-table used disk space from `/column_family/metrics/total_disk_space_used` REST API                                                                                  |

### Analyzers

| Analyzer                                          | Check performed                                                                                                                                                        |
|---------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ClockSourceAnalyzer`                             | Clock source is one of the recommended values: `tsc`, `kvm-clock`, `hyperv_clocksource_tsc_page` or `arch_sys_counter`                                                 |
| `CPUInstructionSetAnalyzer`                       | CPU has the required `sse4_2` flag (skipped on non-x86 architectures)                                                                                                  |
| `CPUScalingAnalyzer`                              | CPU scaling is supported and at least one CPU scaling service is active                                                                                                |
| `CPUSetAnalyzer`                                  | CPU set in `cpuset.conf` is a subset of the CPU mask in `perftune.yaml`                                                                                                |
| `CoredumpAnalyzer`                                | `var-lib-systemd-coredump.mount` is active and coredump sysctl config is correctly set up                                                                              |
| `DeveloperModeAnalyzer`                           | Developer mode is disabled (`DEV_MODE` is not `1` in `dev-mode.conf`)                                                                                                  |
| `RaftEnablementAnalyzer`                          | If `consistent_cluster_management` is enabled: Raft Group0 exists and `group0_upgrade_state` is `use_post_raft_procedures`                                             |
| `RaftTopologyEnablementAnalyzer`                  | All rows in `system.topology` have `upgrade_state = done` (skipped if Consistent Topology is not supported)                                                            |
| `GossipInfoConsistencyAnalyzer`                   | Hosts that do not support Consistent Topology have `TOKENS` and `CDC_GENERATION_ID` in their GossipInfo                                                                |
| `TopologyConsistencyAnalyzer`                     | Host UUID sets are identical across GossipInfo, TokenMetadata, Raft Group0, `system.peers`/`system.local`, and `system.cluster_status`                                 |
| `DriverVersionAnalyzer`                           | Connected client drivers are at or above the minimum required version; warns if below the latest version                                                               |
| `IOSetupAnalyzer`                                 | `io.conf` has `SEASTAR_IO` pointing to `io_properties.yaml`                                                                                                            |
| `KernelVersionAnalyzer`                           | Kernel version is >= 3.15                                                                                                                                              |
| `MemoryTuningAnalyzer`                            | `MEM_CONF` is set in `memory.conf`                                                                                                                                     |
| `NICsAnalyzer`                                    | At least one NIC meets the recommended speed threshold (default 10 Gbps) — skipped by default on AWS and GCP; on AWS: enhanced networking and VPC are enabled          |
| `NodeInstanceTypeAnalyzer`                        | Cloud instance type (AWS i3/i3en/i4i/i7i/i7ie/i8g/i8ge, GCP n2/n2d/z3, Azure Lsv2/Lsv3) is in the recommended list                                                     |
| `NTPStatusAnalyzer`                               | NTP is enabled and the system clock is synchronized (via `timedatectl`)                                                                                                |
| `NTPServicesAnalyzer`                             | At least one NTP service (systemd-timesyncd, chronyd, ntpd, etc.) is active                                                                                            |
| `ChronyStatusAnalyzer`                            | Chrony leap status from `chronyc tracking` is not `Not synchronised`                                                                                                    |
| `ChronyServicesAnalyzer`                          | At least one chrony service (`chronyd` or `chrony`) is active                                                                                                          |
| `ComputerArchitectureAnalyzer`                    | CPU architecture is one of `x86_64`, `arm64`, `aarch64`, `ppc64`                                                                                                       |
| `OSSupportAnalyzer`                               | OS distribution and version is officially supported (Ubuntu, Debian, CentOS ≥7.2, RHEL, Rocky, Amazon Linux 2023)                                                      |
| `PerftuneAnalyzer`                                | All system file and sysctl values match the recommendations from `perftune.py` (based on `perftune.yaml`)                                                              |
| `PerftuneCpuMaskAnalyzer`                         | CPU mask from `perftune.yaml` matches the default CPU mask generated by `perftune.py`                                                                                  |
| `PerftuneYamlAnalyzer`                            | `perftune.yaml` content matches what `scylla_sysconfig_setup` would generate (ignoring `mode` and `irq_cpu_mask`)                                                      |
| `RAIDSetupAnalyzer`                               | If any Scylla data directory is on a software RAID, the RAID level is RAID0                                                                                            |
| `UnusedNVMeDevicesAnalyzer`                       | Warns if NVMe devices are present but not mounted and not used by an active software RAID                                                                              |
| `RAMAnalyzer`                                     | Total RAM and RAM-per-lcore meet minimum (4 GB total, 0.5 GB/lcore) and recommended (16 GB total, 4 GB/lcore) thresholds                                               |
| `RsyslogAnalyzer`                                 | `/etc/rsyslog.d/scylla.conf` exists (rsyslog is configured for Scylla)                                                                                                 |
| `AIOMAXNRAnalyzer`                                | `fs.aio-max-nr` ≥ `shards × 11026 + 65536`                                                                                                                             |
| `AssignedNICsAnalyzer`                            | All NICs through which Scylla addresses route are listed in `perftune.yaml` `nic` field                                                                                |
| `ScheduledMaintenanceEventAnalyzer`               | No pending cloud provider maintenance events (skipped on non-cloud or unsupported platforms)                                                                           |
| `ScyllaBroadcastAddressAnalyzer`                  | `broadcast_address` does not resolve to loopback or 0.0.0.0                                                                                                            |
| `ScyllaClusterSchemaAnalyzer`                     | All cluster nodes share the same schema version                                                                                                                        |
| `ScyllaClusterSystemKeyspacesReplicationAnalyzer` | `system_auth`, `system_distributed`, `system_traces`, and `audit` keyspaces use `NetworkTopologyStrategy` with replication factor ≥ min(3, node count)                 |
| `ScyllaKeyspacesReplicationAnalyzer`              | All keyspaces except known system ones (`system`, `system_schema`, `system_replicated_keys`, `system_distributed_everywhere`) use `NetworkTopologyStrategy`            |
| `ScyllaDeprecatedArgumentsAnalyzer`               | No deprecated `SCYLLA_ARGS` are in use (`--background-writer-scheduling-quota`, `--auto-adjust-flush-quota`, `--load-balance`, `--join-ring`, `--no-handle-interrupt`) |
| `FSFILEMAXAnalyzer`                               | `fs.file-max` ≥ `LimitNOFILE`; warns if below the recommended maximum value                                                                                            |
| `FSNROPENAnalyzer`                                | `fs.nr_open` ≥ `LimitNOFILE`; warns if below the recommended value (1073741816)                                                                                        |
| `ScyllaInternodeCompressionAnalyzer`              | `internode_compression` equals the recommended value (default: `all`)                                                                                                  |
| `ScyllaLimitNOFILEAnalyzer`                       | `LimitNOFILE` ≥ 10000 (minimum); warns if < 500000 (recommended)                                                                                                       |
| `ScyllaListenAddressAnalyzer`                     | `listen_address` does not resolve to loopback or 0.0.0.0                                                                                                               |
| `ScyllaNICsDisksSetupAnalyzer`                    | `SET_NIC_AND_DISKS = yes` in the `scylla-server` sysconfig file                                                                                                        |
| `ScyllaRPCAddressAnalyzer`                        | `rpc_address` does not resolve to loopback or INADDR_ANY                                                                                                               |
| `ScyllaBroadcastRPCAddressAnalyzer`               | `broadcast_rpc_address` does not resolve to loopback or INADDR_ANY                                                                                                     |
| `ScyllaServicesAnalyzer`                          | All required Scylla services (scylla-server, scylla-jmx, node-exporter, scylla-housekeeping, scylla-manager-agent, scylla-fstrim.timer) are active and enabled         |
| `ScyllaSeedsAnalyzer`                             | All seed nodes listed in `scylla.yaml` are reachable                                                                                                                   |
| `ScyllaSnitchAnalyzer`                            | Snitch is provider-appropriate (`Ec2MultiRegionSnitch` on AWS, `GoogleCloudSnitch` on GCP, `GossipingPropertyFileSnitch` otherwise)                                    |
| `ScyllaSSTablesAnalyzer`                          | All SSTable files use the recommended format (auto-detected from `system.config`, default: `me`)                                                                       |
| `STCSInSchemaAnalyzer`                            | No tables or views use `SizeTieredCompactionStrategy`                                                                                                                  |
| `ZstdCompressionLevelAnalyzer`                    | ZSTD `compression_level` in table and view schema and in-memory `system.config` `sstable_compression_user_table_options` is ≤ recommended max (default: 4)             |
| `CloudCPUPlatformAnalyzer`                        | VM CPU platform matches the configured `expected_cpu_platform` (skipped if not configured or not applicable)                                                           |
| `ScyllaSupportAnalyzer`                           | Scylla version is not EOL (OSS ≥ 6.1, Enterprise ≥ 2024.1 by default)                                                                                                  |
| `ScyllaSystemConfigurationFilesAnalyzer`          | Required sysconfig files (`scylla-server`, `scylla-housekeeping`, `scylla-jmx`) are present                                                                            |
| `ScyllaUpdateAnalyzer`                            | Scylla is at the latest available version (fetched from repositories.scylladb.com if not configured)                                                                   |
| `SELinuxAnalyzer`                                 | SELinux is disabled                                                                                                                                                    |
| `StorageTypeAnalyzer`                             | Data directories are on NVMe devices                                                                                                                                   |
| `StorageRAMRatioAnalyzer`                         | Storage-to-RAM ratio is ≤ the recommended value (default: 105:1)                                                                                                       |
| `SwapAnalyzer`                                    | Swap size ≥ min(16 GB, RAM ÷ 3)                                                                                                                                        |
| `XFSAnalyzer`                                     | All Scylla data directories (data, commitlog, hints, view_hints) use XFS                                                                                               |
| `ScyllaConfigurationFileFormatAnalyzer`           | Tri-state (`restriction mode`) fields in `scylla.yaml` use allowed values (`true`, `false`, `warn`, `0`, `1`)                                                          |
| `ScyllaConfigurationConsistencyAnalyzer`          | All values in `scylla.yaml` match the in-memory runtime configuration (`system.config`); all in-memory params not in `scylla.yaml` have a default source               |
| `RaftTopologyRPCStatusAnalyzer`                   | No Raft topology RPC is ongoing/stuck                                                                                                                                  |
| `DisabledCompactionAnalyzer`                      | All tables and views have an active compaction strategy (not `NullCompactionStrategy` and not `enabled: false`)                                                        |
| `BrokenRolePermissionsAnalyzer`                   | Verifies that no role in `system.role_permissions` has a `null` permissions value                                                                                      |

## Configuration
Scylla Doctor doesn't require any additional configuration in order to run. Its defaults are enough.
However, defaults can be overridden through an optional configuration file of using command line arguments.

| Parameter                                                              | Description                                                                                                               |
|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| -h                                                                     | Print help message                                                                                                        |
| -aofe, --abort-on-first-error                                          | abort when the first error happens                                                                                        |
| -cf CONFIGURATION_FILE, --configuration-file CONFIGURATION_FILE        | use a specific configuration file                                                                                         |
| -d, --detailed                                                         | show extra information (if available)                                                                                     |
| -v, --verbose                                                          | show all information gathered                                                                                             |
| -sov SECTION_OPTION_VALUE, --section-option-value SECTION_OPTION_VALUE | set/override the section option value using the provided SECTION_NAME,OPTION_NAME,VALUE_NAME tuple                        |
| -st TEST, --skip-test TEST                                             | skip a given TEST                                                                                                         |
| --save-vitals [Vitals file]                                            | After running collectors, store vitals in a file  (vitals.json by default)                                                |
| --load-vitals [Vitals file]                                            | Instead of running Collectors, load vitals from file (vitals.json by default)                                             |
| --output {full,short,json}                                             | Give out full human-readable report, short launch log, or machine-readable analyzers output for further processing        |
| --print-filter PRINT_FILTER                                            | Regular expression filter to apply to Collectors and Analyzers names before printing. Print only those which name matches |
| --list-parameters [SECTION]                                            | Print configuration parameters and defaults for collectors/analyzers with custom options. Optional SECTION limits output to one component |
| --list-parameters-json                                                 | Output `--list-parameters` as JSON (implies `--list-parameters`)                                                                          |
| --version                                                              | Print Scylla Doctor version and exit                                                                                      |
| --vitals-version [Vitals file]                                         | Print version stored in a vitals file (vitals.json by default) and exit                                                   |
| --ignore-vitals-version                                                | Skip vitals version compatibility check when loading vitals from a file                                                   |

### Filtering output
Output can be filtered using `--print-filter` parameter.

Examples

| Description                                             | Argument                                     |
|---------------------------------------------------------|----------------------------------------------|
| Print only Collector1 and Analyzer1 outputs             | `--print-filter 'Collector1\|Analyzer1'`     |
| Print all outputs BUT those of Collector1 and Analyzer1 | `--print-filter '(?!Collector1\|Analyzer1)'` |

One can add as many items in the constructs above as needed using `|` as a separator.

### Vitals Version check
When loading vitals from a file (`--load-vitals`), Scylla Doctor verifies that the vitals version matches the running tool version.
If they differ, it exits immediately with an error like this (specific version values may vary):

```
Version mismatch: collected: 1.4 analyzer: 1.5
Vitals version mismatch. Use a correct Scylla Doctor version.
```

This check prevents parsing errors due to a vitals format change between different tool versions.
To override this check at your own risk, use `--ignore-vitals-version`.

Use `--version` to print the running Scylla Doctor version.
Use `--vitals-version [/path/to/vitals.json]` to print the version stored in a vitals file.

## Configuration file
Configuration file must have a Microsoft Windows INI format
Following sections are supported:

| Section name      | Description                           |
|-------------------|---------------------------------------|
| DefaultPaths      | Definitions of paths (see more below) |
| CQL               | CQL credentials                       |
| \<Collector name> | Specific Collector parameters         |
| \<Analyzer name>  | Specific Analyzer parameters          |

Note that the configuration file supports a `BasicInterpolation` as described
here: https://docs.python.org/3.8/library/configparser.html#interpolation-of-values.



### DefaultPaths section
| Field name (default value)                 | Description                                                         |
|--------------------------------------------|---------------------------------------------------------------------|
| scylla_directory (`/opt/scylladb`)         | Base directory where all scylla artifacts are installed on the node |
| scylla_directory_config (`/etc/scylla`)    | Location of scylla.yaml                                             |
| scylla_directory_configs (`/etc/scylla.d`) | Location of all generated configuration files, e.g. cpuset.conf     |                                          
| scylla_directory_var (`/var/lib/scylla`)   | Root storage directory                                              | 

### CQL section
Given CQL credentials will be used in order to fetch schema.

| Field name (default value)                                                    | Description                              |
|-------------------------------------------------------------------------------|------------------------------------------|
| user (`cassandra`)                                                            | CQL user name                            |
| password (`cassandra`)                                                        | CQL password                             |
| rpc_address (value of `rpc_address` field in scylla.yaml)                     | CQL RPC address                          |
| native_transport_port (value of `native_transport_port` field in scylla.yaml) | CQL native transport port                |
| use_ssl                                                                       | Whether to use SSL encryption with cqlsh |

`use_ssl` field can be set to any of the following values in order to enable SSL encryption with `cqlsh` (case insensitive):
* `1`
* `yes`
* `true`
* `on`

### \<Collector>|\<Analyzer> section
Every Collector or Analyzer can be skipped using `run` field.
In order to skip a corresponding Collector/Analyzer `run` field should have any of the following values (case insensitive):
* `0`
* `no`
* `false`
* `off`

Any other value or no value would result in executing the corresponding Collector/Analyzer. 

For example to skip `InfrastructureProviderCollector` collector one
can add the following section in the configuration file:

```
[InfrastructureProviderCollector]
run = no
```

or use the following command line option: `-sov InfrastructureProviderCollector,run,no`

Additional Analyzer/Collector specific parameters can be also provided as follows:

```
[SwapAnalyzer]
ram_swap_ratio = 3
```

### Per-collector/analyzer clarifications
#### InfrastructureProviderCollector
This collector is going to try to identify a CPU platform used by a VM and return it in a `data['cpu_platform']`
field. In case it is able to identify a known platform it would set one of the following platform names:

| Known Platform                  | Platform name string |
|---------------------------------|----------------------|
| GCP VMs with Intel Ice Lake     | "Intel Ice Lake"     |
| GCP VMs with Intel Cascade Lake | "Intel Cascade Lake" |
| AWS i3.metal VM                 | "Intel Broadwell"    | 
| AWS i4i VMs                     | "Intel Ice Lake"     |
| Azure Lsv2 VMs                  | "AMD EPIC Naples"    |
| Azure Lsv3 VMs                  | "Intel Ice Lake"     |

In case Scylla Doctor is not executed on one of the platforms above the `data['cpu_platform']` will be either set
to whatever CPU Platform is reported by a corresponding Cloud provider or set to `None`.

### Per-collector/analyzer parameters:
Below are parameters supported by selected Collectors/Analyzers.

#### DriverVersionAnalyzer
| Field name (default value) | Description                                                                                                                   |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| minimum_version (`{}`)     | A key-value JSON with as key a driver type (e.g. Java, Python) and value the minimum allowed driver version (e.g. 3.2).       |
|                            | The minimum driver version is typically considered to be the driver version used in testing for the cluster's Scylla version. |
|                            | If any used client driver is below this minimum version, then it is outdated, and an error will be shown.                     |
| latest_version (`{}`)      | A key-value JSON with as key a driver type (e.g. Java, Go, Rust, etc.) and value the latest driver version that exists.       |
|                            | The latest driver version is the most up-to-date driver version that exists for this driver type.                             |
|                            | If any used client driver is below the latest version a warning will be shown.                                                |
| driver_api_endpoint        | The URL endpoint to use to retrieve minimum or latest driver versions from when not specified by the aforementioned fields.   |
|                            | By default this is 'https://cfqlgypqmoofu6wdoojklzdzhe0lqqso.lambda-url.us-east-2.on.aws/search'                              |

The input JSON in the .ini file for either minimum_version or latest_version can be as follows, and must be indented properly.

```ini
minimum_version = {
    "Java" : "3.14.0",
    "Go": "3.45",
    "Python": "4"
    "CPP": "2.15.2",
    "Rust": "0.5",
    }
```

#### InfrastructureProviderCollector
| Field name (default value) | Description                                                               |
|----------------------------|---------------------------------------------------------------------------|
| timeout (`1`)              | Cloud Provider Metadata Server API access timeout                         |
| retries (`0`)              | Number of retries in case Cloud Provider Metadata Server API access fails |
| retry_interval (`0`)       | Delay in seconds between retries                                          |

#### MaintenanceEventsCollector
| Field name (default value) | Description                                                               |
|----------------------------|---------------------------------------------------------------------------|
| timeout (`1`)              | Cloud Provider Metadata Server API access timeout                         |
| retries (`0`)              | Number of retries in case Cloud Provider Metadata Server API access fails |
| retry_interval (`0`)       | Delay in seconds between retries                                          |

#### ScyllaLogsCollector 
| Field name (default value) | Description                                                                                                     |
|----------------------------|-----------------------------------------------------------------------------------------------------------------|
| since_date                 | Value that will be used with `--since` parameter of `journalctl`. By default `--since` is not going to be used. |

#### ScyllaManagerAgentLogsCollector
| Field name (default value) | Description                                                                                                     |
|----------------------------|-----------------------------------------------------------------------------------------------------------------|
| since_date                 | Value that will be used with `--since` parameter of `journalctl`. By default `--since` is not going to be used. |

#### SystemTabletsCollector
Collects tablet ownership from `system.tablets` into `data.tables` (one entry per keyspace/table with shared `table_id` / `base_table`, plus a `tablets` list of `last_token` / `replicas`). Skipped (not a failure) on Scylla versions predating tablets, where `system.tablets` does not exist. Fully masked from cluster drift comparison (tablet maps move under balancing).

| Field name (default value) | Description                                                                                                                                                                          |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| max_rows (`-1`)            | Maximum number of rows to collect from `system.tablets`. `-1` means no limit (collect all rows). The tablet map scales with #tables x tablet_count and can be large on busy clusters. |

#### LargePartitionsCellsRowsCollector
| Field name (default value) | Description                                                                                              |
|----------------------------|----------------------------------------------------------------------------------------------------------|
| max_rows (`-1`)            | Maximum number of rows to collect from each of the three tables. `-1` means no limit (collect all rows). |

### SystemConfigCollector
| Field name (default value) | Description                                                       |
|----------------------------|-------------------------------------------------------------------|
| string_value_keys          | A coma-separated list of keys that have a string (non-JSON) value |


#### NICsCollector
| Field name (default value) | Description                                                                                                      |
|----------------------------|------------------------------------------------------------------------------------------------------------------|
| skip_nics                  | Comma-separated list of network interface names to omit from collection. Loopback and common virtual/tunnel interfaces (`lo`, `erspan0`, `gre0`, `gretap0`, `sit0`, `ip6tnl0`) are skipped by default; this option adds more. |

#### NICsAnalyzer
| Field name (default value)                                  | Description                                                                                                     |
|-------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| speed (`10000`)                                             | Suggested minimum NIC speed in Mbps                                                                             |
| skip_nic_speed_check (`True` on AWS/GCP, `False` otherwise) | Skip NIC speed threshold check. Defaults to `True` on AWS and GCP (which don't expose link speed via `ethtool`) |

#### RAMAnalyzer
| Field name (default value)            | Description                                       |
|---------------------------------------|---------------------------------------------------|
| ram_minimum_total (`4194304`)         | Minimum recommended total RAM size in KB          |
| ram_minimum_per_lcore (`524288`)      | Minimum recommented RAM per CPU/hyperthread in KB |
| ram_recommended_total (`16777216`)    | Recommended total RAM in KB                       |
| ram_recommended_per_lcore (`4194304`) | Recommended RAM per CPU/hyper-thread in KB        |

#### ScyllaInternodeCompressionAnalyzer
| Field name (default value)      | Description                        |
|---------------------------------|------------------------------------|
| recommended_compression (`all`) | Recommended inter-node compression |

#### ScyllaServicesAnalyzer
Unless specified otherwise all following services must be both `active` and `enabled`:
* `scylla-server` or `scylla`
* `scylla-jmx`
* `node-exporter` or `scylla-node-exporter`
* `scylla-housekeeping-daily` or `scylla-housekeeping`
* `scylla-manager-agent`

| Field name (default value) | Description                                                                             |
|----------------------------|-----------------------------------------------------------------------------------------|
| skip_autostarts_check      | A coma-separated list of services that should be skipped in an enabled/auto-start check |
| disable_autostarts         | A coma-separated list of services that must NOT be enabled/auto-started                 |
| skip_active_check          | A coma-separated list of services that should be skipped in an active service check     |
| disable_active             | A coma-separated list of services that must be inactive                                 |

#### ScyllaSnitchAnalyzer
| Field name (default value) | Description                                                                                                                                                                                                                                          |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| check_provider_snitch      | Verify that a provider-specific snitch is used (e.g. GoogleCloudSnitch on GCE). This field's syntax is the same as of a `run` field. If a provider-specific snitch check is disabled a snitch is expected to be set to `GossipingPropertyFileSnitch` |

#### ScyllaSSTablesAnalyzer
| Field name (default value) | Description                                                                                                                                    |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| recommended_format         | Expected SSTable format. When set, takes priority over the value auto-detected from `system.config`. Defaults to `me` if neither is available. |

#### ScyllaSupportAnalyzer
| Field name (default value)            | Description                                 |
|---------------------------------------|---------------------------------------------|
| oss_minimum_version (`6.1`)           | Minimum supported OSS Scylla version        |
| enterprise_minimum_version (`2024.1`) | Minimum supported Enterprise Scylla version |

#### ScyllaUpdateAnalyzer
| Field name (default value) | Description                                                                                                                                                                                          |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| enterprise_latest_version  | Enterprise Scylla version that should be used as 'latest'. If not provided the current latest version will be used according to the output of https://repositories.scylladb.com/scylla/check_version |
| oss_latest_version         | OSS Scylla version that should be used as 'latest'. If not provided the current latest version will be used according to the output of https://repositories.scylladb.com/scylla/check_version        |

#### StorageRAMRatioAnalyzer
| Field name (default value) | Description                           |
|----------------------------|---------------------------------------|
| ratio (`105`)              | Maximum recommended Disk to RAM ratio |

#### SwapAnalyzer
This Analyzer will verify that the actual amount of swap is greater or equal to `min(swap_minimum_total, RAM/ram_swap_ratio)`

| Field name (default value)      | Description                           |
|---------------------------------|---------------------------------------|
| swap_minimum_total (`16777216`) | Minimum swap partition size in KB     |
| ram_swap_ratio (`3.0`)          | Recommended RAM to swap ratio (float) |  

#### CloudCPUPlatformAnalyzer
Checks if the current VM host has the expected CPU platform.
E.g. on GCP it can be "Intel Ice Lake".
The Analyzer status is going to be `SKIPPED` if `expected_cpu_platform` is not specified.

| Field name (default value) | Description                                                                                 |
|----------------------------|---------------------------------------------------------------------------------------------|
| expected_cpu_platform      | Expected CPU platform name as set by InfrastructureProviderCollector, e.g. "Intel Ice Lake" |

#### DisabledCompactionAnalyzer
| Field name (default value) | Description                                                                                                                |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------|
| ignored_tables             | A comma-separated list of table or view names that should be ignored. A name must be in a `<Keyspace name>.<Table or view name>` form |

#### ZstdCompressionLevelAnalyzer
| Field name (default value) | Description                                                                                                                |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------|
| max_recommended_level (`4`) | Maximum recommended ZSTD compression level; higher levels use slower compression strategies and may increase CPU usage    |
| ignored_tables             | Comma-separated names of tables or views to ignore in schema checks, in `<Keyspace>.<Table or view>` form                  |

#### PerftuneAnalyzer
| Field name (default value) | Description                                                                                              |
|----------------------------|----------------------------------------------------------------------------------------------------------|
| skip_files                 | A comma-separated list of file paths to skip when checking perftune-configured file values               |
| skip_sysctls               | A comma-separated list of sysctl parameter names to skip when checking perftune-configured sysctl values |

For example, to skip checking `/sys/block/sda/queue/scheduler`, `/sys/net/core/somaxconn` and `net.core.rps_sock_flow_entries`:

```
[PerftuneAnalyzer]
skip_files = /sys/block/sda/queue/scheduler, /sys/net/core/somaxconn
skip_sysctls = net.core.rps_sock_flow_entries
```

#### ScyllaConfigurationConsistencyAnalyzer
This analyzer performs two independent checks:

1. **Source validation** — every key present in `scylla.yaml` must have `source = config` in `system.config`; every key absent from `scylla.yaml` must have `source = default` or `source = internal`.
2. **Value validation** — every key present in `scylla.yaml` must have the same value in `system.config`.

| Field name (default value)      | Description                                                                                                  |
|---------------------------------|--------------------------------------------------------------------------------------------------------------|
| skip_source_validation_keys     | A comma-separated list of `system.config` keys to exclude from the **source** consistency check              |
| skip_persisted_validation_keys  | A comma-separated list of `system.config` keys to exclude from the **value** consistency check               |

Both fields accept surrounding whitespace around commas (e.g. `key1, key2` and `key1,key2` are equivalent).

When skip keys are configured, they are always listed in the analyzer output message — both on success and on failure — so the suppression is visible in reports:

```
Scylla configuration is consistent (keys skipped per configuration: ['some_config_key'])
```

Use these options when a known Scylla bug or deployment-specific condition causes a key to legitimately diverge, and you want to silence the false positive until the upstream issue is resolved.

For example, to suppress source and value checks for a specific key:

```
[ScyllaConfigurationConsistencyAnalyzer]
skip_source_validation_keys = some_config_key
skip_persisted_validation_keys = another_config_key, yet_another_key
```
