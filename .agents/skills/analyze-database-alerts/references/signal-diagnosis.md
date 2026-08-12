# Database signal collection

Use this reference only to map a normalized alert signal to relevant read-only observations.
Do not use it to generate or rank causes before collection completes. The table does not prove a
cause. Vendor-specific names vary, and deployed local PDF and external knowledge sources are peer
operational guidance.

| Symptom family | Read-only observations to collect | Interpretation boundary |
| --- | --- | --- |
| High query latency | latency percentiles by query, wait categories, plan identity, host I/O and CPU, dependency timing | A correlated high metric alone is not a root cause. |
| Connection saturation | active versus idle sessions, connection age, pool metrics, arrival rate, configured limit and its history | Reaching a limit does not justify changing it. |
| High CPU | top workload fingerprints, execution counts and time, process breakdown, run queue, maintenance activity | High CPU is the reported resource state until causal evidence is analyzed. |
| Memory pressure or OOM | process memory, cache behavior, session count, spill metrics, kernel OOM records | Low free memory alone does not establish a leak. |
| Disk capacity | usage by directory or object, log retention position, temporary usage, growth rate, cleanup blockers | Capacity pressure alone does not justify deleting data or logs. |
| I/O saturation | latency and queue depth by device, read/write split, database flush or checkpoint metrics, workload timing | IOPS alone does not establish storage health or causality. |
| Lock or deadlock | blocker and waiter graph, transaction age, object identity, deadlock record, query fingerprint | A blocked query is not necessarily the blocker. |
| Replication lag | generated and applied positions, apply rate, network health, replica I/O, transaction timeline | One network sample alone does not establish the cause of lag. |
| Availability | health transitions, process exit record, resource events, network path, consensus state, authentication errors | A failed health check alone does not prove a database crash. |
| Throughput drop | request arrival rate, completed rate, queue depth, throttling signals, wait profile | Lower throughput alone does not establish a database regression. |

## Engine-specific collection vocabulary

Use these terms only to locate relevant metrics, logs, and read-only state after the alert target
confirms the engine. Do not turn the vocabulary into causes during collection.

### PostgreSQL

Collect WAL generation and replay, checkpoint, autovacuum, table or index size, lock graph, long
transaction, query plan, temporary spill, and replica conflict observations when relevant to the
reported signal.

### MySQL or compatible engines

Collect InnoDB buffer-pool, redo and binlog, metadata lock, row lock, history-list, purge, temporary
table, query-plan, and replica I/O versus SQL/apply observations when relevant to the signal.

### TiDB, TiKV, and PD

Collect region or key distribution, coprocessor load, Raft proposal and apply timing, store
pressure, compaction, scheduler activity, PD availability, timestamp service, and resolved-ts
observations when relevant. Keep SQL-layer, storage-layer, and control-plane evidence separately
scoped.

## Collection quality

Prefer evidence that is:

1. collected during the alert window;
2. scoped to the affected database object or node;
3. produced by the affected system;
4. successful and untruncated;
5. directly relevant to the normalized alert signal.

During collection, record temporal order without interpreting it. After all selected collection is
terminal, the analysis phase may establish a causal mechanism only when the complete evidence
supports it. Otherwise return no root cause.
