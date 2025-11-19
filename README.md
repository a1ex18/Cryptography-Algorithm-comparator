# Cryptographic Algorithm Comparator

An interactive dashboard that benchmarks classical (RSA, ECC, SHA-256) and quantum-inspired (BB84) primitives with live charts. The backend streams progress updates over WebSockets while the frontend renders nanosecond-level metrics in a friendly format.

## Features

- ⚡ Real-time progress streaming via Flask-Socket.IO with resilient `safe_emit` helpers.
- ⏱️ Nanosecond precision timing converted to human-friendly ms/μs in the UI.
- 🔁 Parallel benchmarking for RSA, ECC (ECDH), SHA-256 hashing, and BB84 quantum key distribution simulation.
- 📊 Chart.js visualisations for per-algorithm stages and cross-algorithm totals.

## Project layout

```
├── backend/
│   ├── app.py          # Canonical Flask-Socket.IO server entrypoint
│   └── requirements.txt
├── static/
│   ├── css/style.css   # Tailored dashboard styling
│   └── js/main.js      # Frontend controller, charts, and state management
├── templates/index.html # Single-page dashboard served by Flask
└── major.py            # Standalone benchmarking script (offline CLI demo)
```

## Quick start

1. Create and activate a virtual environment (recommended):
	```powershell
	python -m venv .venv
	.\.venv\Scripts\Activate.ps1
	```
2. Install backend dependencies:
	```powershell
	pip install -r backend/requirements.txt
	```
3. Launch the Socket.IO server:
	```powershell
	python backend/app.py
	```
4. Open `http://localhost:5000` in your browser and click **Run All Benchmarks**.

## Canonical backend entrypoint

`backend/app.py` is the authoritative server module. It exposes the Flask application, registers Socket.IO events, and orchestrates each algorithm through `run_cpu_benchmark` wrappers to capture nanosecond timings. The `safe_emit` helper is used throughout to shield the websocket channel from transient errors while broadcasting structured progress payloads to the frontend.

## Timing units

- Internal measurements use `time.perf_counter_ns()` for maximum precision.
- The frontend formats RSA/ECC totals in milliseconds and sub-operations (encrypt/decrypt) in microseconds so that small values remain legible.
- SHA-256 averages are surfaced in microseconds and BB84 totals in milliseconds. The comparison chart converts every total to milliseconds for a consistent scale.

## Security notice

- **RSA:** Keys are generated on the fly without hardened randomness, padding, or key storage. The implementation is for benchmarking demonstrations only.
- **ECC:** Curve operations omit side-channel protections and production-grade key management. Treat derived metrics as educational timing data, not security guidance.
- **BB84:** The quantum key distribution routine is a simplified simulation and does not provide real-world cryptographic guarantees.

Please avoid reusing any outputs, keys, or timings from this repository in security-critical environments.