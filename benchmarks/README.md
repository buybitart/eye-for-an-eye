# P5 Benchmark Harness

Run from the repository root with CPython 3.12 and the locked capture/test extras. Benchmarks are outside the production package. No new runtime dependency was added.

~~~text
uv sync --frozen --extra capture --extra enrichment --extra test --extra lint
uv run --frozen --no-sync python -m pytest -q
uv run --frozen --no-sync python -m benchmarks.run --case packet_parsing --output benchmarks/results/local-packets.json
uv run --frozen --no-sync python -m benchmarks.run --case packet_parsing --profile --output benchmarks/results/local-profile.json
uv run --frozen --no-sync python -m benchmarks.run --case correlation --full --output benchmarks/results/local-memory.json
uv run --frozen --no-sync python -m benchmarks.run --case api_large --full --output benchmarks/results/local-api-50k.json
uv run --frozen --no-sync python -m benchmarks.soak --seconds 900 --output benchmarks/results/local-soak-15m.json
~~~

This Windows session used .p1-check-venv/Scripts/python.exe instead of uv run. Installing extras may require network; workloads themselves never use external destinations. Existing P5 evidence is in results/p5; use new output names for reproduction.

Cases: packet_parsing, fingerprinting, correlation, cache, deception, storage, tcp_listener, api, api_large, enrichment, queue, lifecycle, autonomous. Execute sequentially. --full increases finite sample sizes; it does not remove limits. See [workload catalogue](workloads/__init__.py) and [methodology](../docs/BENCHMARKING.md).

| Scope | Bounds |
|---|---|
| Each ordinary case | Parent watchdog: 180 wall seconds, 150 CPU seconds, 512 MiB worker RSS, 8 MiB output |
| TCP | Loopback, 128 active server connections, 8 client workers; idle 10/100/128; listener lifetime 25 seconds |
| Enrichment | Local mock provider, 1 child, queue 4, provider timeout 0.4 seconds; never live RDAP |
| Correlation full | 100,000 events, 50,000 identities, 10,000 retained sources, 32 MiB accounted state |
| Large API | 10,000 / 50,000 rows; existing query/page/response/time bounds |
| Soak | Explicit 15..3540 seconds plus 60 seconds watchdog allowance; 60 offered events/s, 16 sources, 2,000 retained rows |
| Autonomous | 800 events (3,000 with --full) from 4 sources, four configurations back to back in one child; shadow mode, no enforcer attached |

The parent watches the benchmark root process; provider descendants are separately bounded by EnrichmentService. Windows root CPU/RSS are measured; Linux /proc RSS fallback is provided, CPU monitoring there is unavailable. Unsupported platforms retain the wall/output watchdog. No aggregate machine-memory guarantee is claimed. Cleanup closes owned sockets, processes, threads and SQLite connections and removes only the case's temporary directory. All temporary files live under .p5-check/tmp.

Raw JSON includes configuration, Python/OS/CPU/RAM/dependencies, catalogue version, seed, production source hash, counts, latency percentiles, resources and watchdog limits. Microsecond results can have zero CPU time because the Windows CPU clock is coarse. cProfile runs include allocation sampling and interpreter overhead; never use their throughput as the unprofiled baseline.

~~~text
python -m pytest -q tests/test_p5_benchmark_smoke.py tests/test_p5_performance_contracts.py tests/test_p5_backpressure.py tests/test_p5_storage_batch.py
python -m benchmarks.report
python -m benchmarks.report --check
~~~

The first command is stable CI smoke: semantic bounds, atomicity, isolation and cleanup, without machine-speed assertions. The report command reads saved P5 results and generates 50 comparison rows. --check is an optional same-host review gate for the three repeated principal workloads, not a timing gate for every commit. Full benchmarks and soak remain explicit operator jobs.
