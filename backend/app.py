from flask import Flask, render_template
from flask_socketio import SocketIO
import statistics
import time
import sys
import os

# Add parent directory to path to import major.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from major import sha256_hash, bb84_simulate

from crypto_benchmarks import BenchmarkError, benchmark_ecdh, benchmark_rsa
from security import RNG, run_guard

app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')
app.config['SECRET_KEY'] = 'crypto-viz-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

ALLOWED_RSA_BITS = {256, 512, 1024, 2048, 3072, 4096}
MIN_RSA_MSG_SIZE = 1
MAX_RSA_MSG_SIZE = 4096
MIN_REPEATS = 1
MAX_REPEATS = 500
MIN_ERROR_RATE = 0.0
MAX_ERROR_RATE = 1.0
CURVE_MAP = {
    "secp192r1": "secp192r1",
    "secp256r1": "secp256r1",
    "x25519": "x25519",
}


def safe_emit(event, payload, *, allow_error=True):
    try:
        socketio.emit(event, payload)
    except Exception as exc:
        app.logger.exception("Socket emit failed for event %s", event, exc_info=exc)
        if allow_error and event != "error":
            try:
                socketio.emit(
                    "error",
                    {"message": str(exc), "source_event": event},
                )
            except Exception:
                app.logger.exception("Failed to emit error event", exc_info=True)
def _coerce_int(value, name, *, minimum=None, maximum=None):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and ivalue < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and ivalue > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return ivalue


def _coerce_float(value, name, *, minimum=None, maximum=None):
    try:
        fvalue = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a float")
    if minimum is not None and fvalue < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and fvalue > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return fvalue


def validate_payload(params):
    if not isinstance(params, dict):
        raise ValueError("Payload must be a JSON object")

    sanitized = {"rsa": {}, "ecc": {}, "sha256": {}, "bb84": {}}

    rsa_params = params.get("rsa", {})
    if not isinstance(rsa_params, dict):
        raise ValueError("rsa must be an object")
    bits = _coerce_int(rsa_params.get("bits", 512), "RSA key size", minimum=256, maximum=4096)
    if bits not in ALLOWED_RSA_BITS:
        raise ValueError(f"RSA key size must be one of {sorted(ALLOWED_RSA_BITS)}")
    msg_size = _coerce_int(
        rsa_params.get("msg_size", 32),
        "RSA message size",
        minimum=MIN_RSA_MSG_SIZE,
        maximum=MAX_RSA_MSG_SIZE,
    )
    rsa_repeats = _coerce_int(
        rsa_params.get("repeats", 2),
        "RSA repeats",
        minimum=MIN_REPEATS,
        maximum=MAX_REPEATS,
    )
    sanitized["rsa"] = {"bits": bits, "msg_size": msg_size, "repeats": rsa_repeats}

    ecc_params = params.get("ecc", {})
    if not isinstance(ecc_params, dict):
        raise ValueError("ecc must be an object")
    curve_name = ecc_params.get("curve", "secp192r1")
    if curve_name not in CURVE_MAP:
        raise ValueError(f"Unsupported ECC curve '{curve_name}'")
    ecc_repeats = _coerce_int(
        ecc_params.get("repeats", 10),
        "ECC repeats",
        minimum=MIN_REPEATS,
        maximum=MAX_REPEATS,
    )
    sanitized["ecc"] = {"curve": curve_name, "repeats": ecc_repeats}

    sha_params = params.get("sha256", {})
    if not isinstance(sha_params, dict):
        raise ValueError("sha256 must be an object")
    sizes = sha_params.get("sizes")
    if sizes is None and "size" in sha_params:
        sizes = [sha_params["size"]]
    if sizes is None:
        sizes = [128]
    if isinstance(sizes, (int, str)):
        sizes = [sizes]
    if not isinstance(sizes, (list, tuple)) or not sizes:
        raise ValueError("SHA-256 sizes must be a non-empty array")
    sanitized_sizes = []
    for idx, size in enumerate(sizes, start=1):
        sanitized_sizes.append(
            _coerce_int(
                size,
                f"SHA-256 size #{idx}",
                minimum=1,
                maximum=65536,
            )
        )
    sha_repeats = _coerce_int(
        sha_params.get("repeats", 50),
        "SHA-256 repeats",
        minimum=MIN_REPEATS,
        maximum=MAX_REPEATS,
    )
    sanitized["sha256"] = {"sizes": sanitized_sizes, "repeats": sha_repeats}

    bb84_params = params.get("bb84", {})
    if not isinstance(bb84_params, dict):
        raise ValueError("bb84 must be an object")
    qubit_counts = bb84_params.get("qubit_counts")
    if qubit_counts is None and "qubit_count" in bb84_params:
        qubit_counts = [bb84_params["qubit_count"]]
    if qubit_counts is None:
        qubit_counts = [128]
    if isinstance(qubit_counts, (int, str)):
        qubit_counts = [qubit_counts]
    if not isinstance(qubit_counts, (list, tuple)) or not qubit_counts:
        raise ValueError("BB84 qubit counts must be a non-empty array")
    sanitized_qubits = []
    for idx, count in enumerate(qubit_counts, start=1):
        sanitized_qubits.append(
            _coerce_int(
                count,
                f"BB84 qubit count #{idx}",
                minimum=1,
                maximum=1_000_000,
            )
        )
    bb84_repeats = _coerce_int(
        bb84_params.get("repeats", 5),
        "BB84 repeats",
        minimum=MIN_REPEATS,
        maximum=MAX_REPEATS,
    )
    error_rate = _coerce_float(
        bb84_params.get("error_rate", 0.01),
        "BB84 error rate",
        minimum=MIN_ERROR_RATE,
        maximum=MAX_ERROR_RATE,
    )
    sanitized["bb84"] = {
        "qubit_counts": sanitized_qubits,
        "repeats": bb84_repeats,
        "error_rate": error_rate,
    }

    return sanitized

def emit_progress(algorithm, stage, progress, data=None):
    """Helper to emit progress updates"""
    safe_emit(
        "algorithm_progress",
        {
            "algorithm": algorithm,
            "stage": stage,
            "progress": progress,
            "data": data,
            "timestamp": time.time(),
        },
    )

def _with_run_payload(run_id, payload):
    merged = dict(payload or {})
    merged['run_id'] = run_id
    return merged


def run_rsa_with_progress(bits=512, msg_size=32, repeats=2, run_id=None):
    """Run RSA with live progress updates using hardened primitives."""

    if run_id is None or not run_guard.is_active(run_id):
        return

    def _progress(stage: str, value: int, payload: dict[str, object]) -> None:
        if not run_guard.is_active(run_id):
            return
        emit_progress('rsa', stage, value, _with_run_payload(run_id, payload))

    try:
        benchmark_rsa(bits=bits, message_size=msg_size, repeats=repeats, progress=_progress)
    except (BenchmarkError, ValueError) as exc:
        emit_progress('rsa', 'error', 0, _with_run_payload(run_id, {'error': str(exc)}))


def run_ecc_with_progress(curve_name='secp192r1', repeats=10, run_id=None):
    """Run ECC (ECDH) with live progress updates."""

    if run_id is None or not run_guard.is_active(run_id):
        return

    resolved_curve = CURVE_MAP.get(curve_name, curve_name)

    def _progress(stage: str, value: int, payload: dict[str, object]) -> None:
        if not run_guard.is_active(run_id):
            return
        emit_progress('ecc', stage, value, _with_run_payload(run_id, payload))

    try:
        benchmark_ecdh(curve=resolved_curve, repeats=repeats, progress=_progress)
    except (BenchmarkError, ValueError) as exc:
        emit_progress('ecc', 'error', 0, _with_run_payload(run_id, {'error': str(exc)}))

def run_sha256_with_progress(sizes=[16, 128, 1024], repeats=50, run_id=None):
    """Run SHA-256 with live progress updates"""
    if run_id is None or not run_guard.is_active(run_id):
        return
    try:
        emit_progress('sha256', 'started', 0, _with_run_payload(run_id, {'sizes': sizes, 'repeats': repeats}))
        
        results = {}
        total_tests = len(sizes)
        total_ns = 0
        
        for idx, s in enumerate(sizes):
            if not run_guard.is_active(run_id):
                return
            emit_progress('sha256', 'hashing', idx * 100 // total_tests, _with_run_payload(run_id, {
                'status': f'Hashing {s} bytes...',
                'size': s
            }))
            
            times_ns = []
            for i in range(repeats):
                if not run_guard.is_active(run_id):
                    return
                t_ns = time.perf_counter_ns()
                sha256_hash(RNG.bytes(s))
                times_ns.append(time.perf_counter_ns() - t_ns)
                
                if i % 10 == 0:  # Update every 10 iterations
                    progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                    emit_progress('sha256', 'hashing', progress, _with_run_payload(run_id, {
                        'status': f'Hashing {s} bytes ({i+1}/{repeats})',
                        'size': s
                    }))
            
            avg_ns = statistics.mean(times_ns)
            std_ns = statistics.pstdev(times_ns) if len(times_ns) > 1 else 0.0
            median_ns = statistics.median(times_ns)
            results[str(s)] = {
                'avg_ns': avg_ns,
                'std_ns': std_ns,
                'median_ns': median_ns
            }
            total_ns += sum(times_ns)
        
        # Complete
        emit_progress('sha256', 'complete', 100, _with_run_payload(run_id, {
            'results': results,
            'total_time_ns': total_ns
        }))
        
    except Exception as e:
        emit_progress('sha256', 'error', 0, _with_run_payload(run_id, {'error': str(e)}))


def run_bb84_with_progress(qubit_counts=[128, 512], repeats=5, error_rate=0.01, run_id=None):
    """Run BB84 with live progress updates"""
    if run_id is None or not run_guard.is_active(run_id):
        return
    try:
        emit_progress('bb84', 'started', 0, _with_run_payload(run_id, {
            'qubit_counts': qubit_counts,
            'repeats': repeats,
            'error_rate': error_rate
        }))
        
        results = {}
        total_tests = len(qubit_counts)
        total_ns = 0
        
        for idx, q in enumerate(qubit_counts):
            if not run_guard.is_active(run_id):
                return
            emit_progress('bb84', 'simulating', idx * 100 // total_tests, _with_run_payload(run_id, {
                'status': f'Simulating {q} qubits...',
                'qubits': q
            }))
            
            times_ns = []
            errs = []
            
            for i in range(repeats):
                if not run_guard.is_active(run_id):
                    return
                t0 = time.perf_counter_ns()
                key, err = bb84_simulate(q, channel_error_rate=error_rate)
                t1 = time.perf_counter_ns()
                times_ns.append(t1 - t0)
                errs.append(err)
                
                progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                emit_progress('bb84', 'simulating', progress, _with_run_payload(run_id, {
                    'status': f'BB84 {q} qubits ({i+1}/{repeats})',
                    'qubits': q,
                    'error': err,
                    'key_length': len(key)
                }))
            
            avg_ns = statistics.mean(times_ns)
            std_ns = statistics.pstdev(times_ns) if len(times_ns) > 1 else 0.0
            median_ns = statistics.median(times_ns)
            results[str(q)] = {
                'avg_ns': avg_ns,
                'std_ns': std_ns,
                'median_ns': median_ns,
                'avg_error': statistics.mean(errs)
            }
            total_ns += sum(times_ns)
        
        # Complete
        emit_progress('bb84', 'complete', 100, _with_run_payload(run_id, {
            'results': results,
            'total_time_ns': total_ns
        }))
        
    except Exception as e:
        emit_progress('bb84', 'error', 0, _with_run_payload(run_id, {'error': str(e)}))

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('run_benchmarks')
def handle_run_benchmarks(params):
    """Run all algorithms in parallel with user-specified parameters"""
     
    try:
        validated = validate_payload(params or {})
    except ValueError as exc:
        safe_emit(
            "error",
            {"message": str(exc), "source_event": "run_benchmarks"},
            allow_error=False,
        )
        return

    rsa_params = validated["rsa"]
    ecc_params = validated["ecc"]
    sha256_params = validated["sha256"]
    bb84_params = validated["bb84"]

    run_id = run_guard.start()

    try:
        socketio.start_background_task(
            run_rsa_with_progress,
            rsa_params["bits"],
            rsa_params["msg_size"],
            rsa_params["repeats"],
            run_id,
        )
        socketio.start_background_task(
            run_ecc_with_progress,
            ecc_params["curve"],
            ecc_params["repeats"],
            run_id,
        )
        socketio.start_background_task(
            run_sha256_with_progress,
            sha256_params["sizes"],
            sha256_params["repeats"],
            run_id,
        )
        socketio.start_background_task(
            run_bb84_with_progress,
            bb84_params["qubit_counts"],
            bb84_params["repeats"],
            bb84_params["error_rate"],
            run_id,
        )
    except Exception as exc:
        safe_emit(
            "error",
            {"message": f"Failed to start benchmarks: {exc}", "source_event": "run_benchmarks"},
            allow_error=False,
        )
        return

    safe_emit('benchmarks_started', {'message': 'All algorithms started with custom parameters', 'run_id': run_id})

@socketio.on('connect')
def handle_connect():
     print('Client connected')
     safe_emit('connected', {'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
     print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)