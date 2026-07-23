# Database signal diagnosis

Use this reference to generate hypotheses and choose evidence that distinguishes them. The table
does not prove a cause. Vendor-specific names vary, and an approved local PDF runbook remains the
authoritative source for operational guidance.

| Symptom family | Candidate mechanisms | Discriminating read-only evidence | Common false inference |
| --- | --- | --- | --- |
| High query latency | lock waits, plan regression, I/O latency, CPU queueing, remote dependency | latency percentiles by query, wait categories, plan identity, host I/O and CPU, dependency timing | “CPU is high, therefore CPU caused latency” |
| Connection saturation | traffic surge, pool leak, slow requests retaining sessions, long or idle transactions, reduced limit | active versus idle sessions, connection age, pool metrics, arrival rate, limit history | “max connections reached, therefore increase the limit” |
| High CPU | expensive queries, concurrency spike, plan change, background maintenance or compaction, host contention | top workload fingerprints, execution counts and time, process breakdown, run queue, maintenance activity | “high CPU is the root cause” |
| Memory pressure or OOM | working-set growth, cache or buffer change, sort/hash spill pressure, connection growth, co-located workload | process memory, cache hit behavior, session count, spill metrics, kernel OOM record | “low free memory means memory leak” |
| Disk capacity | data growth, WAL/binlog retention, temporary spill, snapshots or backups, compaction debt | usage by directory or object, log retention position, temp usage, growth rate, cleanup blockers | “delete logs immediately” |
| I/O saturation | random reads from plan regression, checkpoint or flush burst, compaction, backup, noisy neighbor | latency and queue depth by device, read/write split, database flush/checkpoint metrics, workload timing | “high IOPS means storage is healthy” |
| Lock or deadlock | inconsistent access order, long transaction, hot row or metadata lock, DDL interaction | blocker/waiter graph, transaction age, object identity, deadlock record, query fingerprint | “the blocked query is the blocker” |
| Replication lag | write burst, apply bottleneck, network loss, storage latency, long transaction, replay conflict | generated versus applied position, apply rate, network health, replica I/O, transaction timeline | “network latency alone caused lag” |
| Availability | process crash, resource exhaustion, network or DNS path, quorum loss, certificate or authentication failure | health transitions, process exit reason, resource events, network path, consensus state, auth error | “health check failure proves database crash” |
| Throughput drop | workload reduction, queueing, throttling, contention, downstream backpressure, plan regression | request arrival rate, completed rate, queue depth, throttling signals, wait profile | “lower throughput always means database regression” |

## Engine-specific hypothesis vocabulary

Use these terms only when the alert target confirms the engine.

### PostgreSQL

Consider WAL generation and replay, checkpoints, autovacuum, table or index bloat, lock graphs,
long transactions, query plans, temp spills, and replica conflicts. A vacuum or checkpoint event
is temporal context until evidence connects it to the symptom.

### MySQL or compatible engines

Consider InnoDB buffer-pool behavior, redo and binlog pressure, metadata locks, row locks, history
list growth, purge lag, temporary tables, query plans, and replica I/O versus SQL/apply delay.

### TiDB, TiKV, and PD

Consider region or key hotspots, coprocessor load, Raft proposal and apply delay, store pressure,
compaction, scheduler activity, PD availability, timestamp services, and resolved-ts lag. Separate
SQL-layer latency from storage-layer and control-plane evidence.

## Evidence selection

Prefer evidence that is:

1. collected during the alert window;
2. scoped to the affected database object or node;
3. produced by the system that owns the suspected mechanism;
4. successful and untruncated;
5. capable of contradicting as well as supporting the hypothesis.

When two signals move together, search for a mechanism and a temporal ordering. If neither can be
established, keep the cause `UNKNOWN`.
