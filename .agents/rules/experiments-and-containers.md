# Container & Experiment Harness Guidelines

## Container Engine Usage
- **Development Default**: Prefer **Podman** for regular local building, testing, and container management (`podman compose`, `podman build`).
- **Chaos Experiments**: Use **Docker** (with `--docker-activate` where applicable) strictly when running Pumba-based chaos experiments or benchmarks due to Pumba's daemon and socket requirements.
- **Compose Stacks**:
  - `docker-compose.yml`: Keep clean for standard development (no chaos daemons or socket mounts); compatible with both Podman and Docker.
  - `docker-compose.experiments.yml`: Dedicated chaos/benchmark stack with Pumba and socket bindings.

## Experiment Scripts & Telemetry Architecture
- **Specialized Experiment Scripts**:
  - Keep scripts in `experiments/` modular and pluggable.
  - Generic resource usage (CPU/RAM time-series via `docker stats`) is logged by `run-experiments.sh`, but experiment scripts are encouraged to spin up dedicated databases or logs for domain-specific metrics (e.g. network delay vs. reconciliation load, temporal accusation density, message convergence).
- **Harness Responsibilities (`run-experiments.sh`)**:
  - Manage experiment timeouts (`-t <duration>`) and process lifecycles.
  - Ensure clean container teardown (`docker compose stop` / `docker compose down`) on timeout, completion, or signal interruption.
  - Log time-series metrics to SQLite using `PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE TRANSACTION;`.
  - Restore file ownership (`chown -R $REAL_USER`) on `experiment_results/` and `experiments/.venv` when executed under `sudo`.

## Python Tooling & Plotting Standards
- **Always Use `uv`**: Prefer `uv` for managing virtual environments and running Python scripts (`uv run`, `uv pip install`, `uv venv`).
- **Plotting Structure**:
  - Keep plotting scripts and isolated environments inside `experiments/` (e.g. `experiments/.venv`).
  - Plot relative elapsed seconds ($t=0\text{s}$) on X-axes and dynamically scale Y-axes to actual data ranges.
