from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import importlib
import multiprocessing
import secrets
import statistics
import threading
import time
import sys
import os

# Add parent directory to path to import major.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from major import *

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
    "secp192r1": SECP192_TEST,
    "secp256r1": SECP256R1,
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


def _cpu_benchmark_worker(queue, module_name, func_name, args, kwargs):
    start = time.perf_counter()
    try:
        func = getattr(importlib.import_module(module_name), func_name)
        result = func(*args, **kwargs)
        queue.put({"result": result, "duration": time.perf_counter() - start})
    except Exception as exc:
        queue.put({"error": str(exc)})


def run_cpu_benchmark(func, *args, **kwargs):
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_cpu_benchmark_worker,
        args=(queue, func.__module__, func.__name__, args, kwargs),
    )
    process.start()
    process.join()
    if queue.empty():
        raise RuntimeError("Benchmark process returned no data")
    outcome = queue.get()
    if "error" in outcome:
        raise RuntimeError(outcome["error"])
    return outcome["result"], outcome["duration"]


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

def run_rsa_with_progress(bits=512, msg_size=32, repeats=2):
     """Run RSA with live progress updates"""
     try:
         emit_progress('rsa', 'started', 0, {'bits': bits, 'msg_size': msg_size})
         
         # Key generation
         emit_progress('rsa', 'keygen', 10, {'status': f'Generating {bits}-bit prime numbers...'})
         time.sleep(0.1)
         try:
            (pub, priv), gen_time = run_cpu_benchmark(rsa_keygen, bits)
         except RuntimeError as exc:
            emit_progress('rsa', 'error', 0, {'error': f'RSA key generation failed: {exc}'})
            return
         emit_progress('rsa', 'keygen', 30, {
             'status': 'Keys generated',
                 'time': gen_time,
             'modulus_bits': pub[0].bit_length()
         })
         
         # Prepare message
         msg = secrets.token_bytes(msg_size)
         emit_progress('rsa', 'prepare', 40, {'status': f'Message prepared ({msg_size} bytes)', 'size': msg_size})
         
         # Encryption
         emit_progress('rsa', 'encrypt', 50, {'status': 'Encrypting...'})
         enc_samples_ns = []
         chunks = None
         for i in range(repeats):
            t = time.perf_counter_ns()
            chunks = rsa_encrypt_bytes(pub, msg)
            enc_samples_ns.append(time.perf_counter_ns() - t)
            emit_progress('rsa', 'encrypt', 50 + (i+1) * 15 // repeats, {
                'status': f'Encryption {i+1}/{repeats}',
                'chunks': len(chunks)
            })
         enc_avg_ns = statistics.mean(enc_samples_ns)
         enc_std_ns = statistics.pstdev(enc_samples_ns) if len(enc_samples_ns) > 1 else 0.0
         
         # Decryption
         if chunks is None:
             raise RuntimeError('RSA encryption produced no chunks to decrypt')

         emit_progress('rsa', 'decrypt', 70, {'status': 'Decrypting...'})
         dec_samples_ns = []
         for i in range(repeats):
            t = time.perf_counter_ns()
            recovered = rsa_decrypt_bytes(priv, chunks)
            dec_samples_ns.append(time.perf_counter_ns() - t)
            emit_progress('rsa', 'decrypt', 70 + (i+1) * 20 // repeats, {
                'status': f'Decryption {i+1}/{repeats}'
            })
         dec_avg_ns = statistics.mean(dec_samples_ns)
         dec_std_ns = statistics.pstdev(dec_samples_ns) if len(dec_samples_ns) > 1 else 0.0

         keygen_ns = int(gen_time * 1_000_000_000)
         total_time_ns = keygen_ns + sum(enc_samples_ns) + sum(dec_samples_ns)
         
         # Complete
         emit_progress('rsa', 'complete', 100, {
             'keygen_stats': {
                 'avg_ns': keygen_ns,
                 'std_ns': 0.0
             },
             'encrypt_stats': {
                 'avg_ns': enc_avg_ns,
                 'std_ns': enc_std_ns
             },
             'decrypt_stats': {
                 'avg_ns': dec_avg_ns,
                 'std_ns': dec_std_ns
             },
             'total_time_ns': total_time_ns
         })
         
     except Exception as e:
         emit_progress('rsa', 'error', 0, {'error': str(e)})

def run_ecc_with_progress(curve_name='secp192r1', repeats=10):
    """Run ECC with live progress updates"""
    try:
        # Select curve (for now only secp192r1 is implemented)
        curve = CURVE_MAP[curve_name]
        emit_progress('ecc', 'started', 0, {'curve': curve.name, 'repeats': repeats})
        
        # Key generation
        emit_progress('ecc', 'keygen', 10, {'status': 'Generating key pairs...'})
        pairs = []
        keygen_samples = []
        for i in range(repeats):
            t0 = time.perf_counter_ns()
            pairs.append(ecc_keygen(curve))
            t1 = time.perf_counter_ns()
            keygen_samples.append(t1 - t0)
            emit_progress('ecc', 'keygen', 10 + (i+1) * 40 // repeats, {
                'status': f'Generated {i+1}/{repeats} pairs'
            })
        keygen_avg_ns = statistics.mean(keygen_samples)
        keygen_std_ns = statistics.pstdev(keygen_samples) if len(keygen_samples) > 1 else 0.0
        
        # ECDH shared secret
        emit_progress('ecc', 'ecdh', 50, {'status': 'Computing shared secrets...'})
        shared_samples = []
        for i in range(repeats):
            d1, Q1 = pairs[i]
            d2, Q2 = pairs[(i+1) % repeats]
            t0 = time.perf_counter_ns()
            s1 = ecdh_shared_secret(d1, Q2, curve)
            s2 = ecdh_shared_secret(d2, Q1, curve)
            t1 = time.perf_counter_ns()
            shared_samples.append(t1 - t0)
            emit_progress('ecc', 'ecdh', 50 + (i+1) * 45 // repeats, {
                'status': f'ECDH {i+1}/{repeats}',
                'matched': s1 == s2
            })
        shared_avg_ns = statistics.mean(shared_samples)
        shared_std_ns = statistics.pstdev(shared_samples) if len(shared_samples) > 1 else 0.0
        
        # Complete
        total_ns = sum(keygen_samples) + sum(shared_samples)
        emit_progress('ecc', 'complete', 100, {
            'keygen_stats': {
                'avg_ns': keygen_avg_ns,
                'std_ns': keygen_std_ns
            },
            'shared_stats': {
                'avg_ns': shared_avg_ns,
                'std_ns': shared_std_ns
            },
            'total_time_ns': total_ns
        })
        
    except Exception as e:
        emit_progress('ecc', 'error', 0, {'error': str(e)})

def run_sha256_with_progress(sizes=[16, 128, 1024], repeats=50):
    """Run SHA-256 with live progress updates"""
    try:
        emit_progress('sha256', 'started', 0, {'sizes': sizes, 'repeats': repeats})
        
        results = {}
        total_tests = len(sizes)
        total_ns = 0
        
        for idx, s in enumerate(sizes):
            emit_progress('sha256', 'hashing', idx * 100 // total_tests, {
                'status': f'Hashing {s} bytes...',
                'size': s
            })
            
            times_ns = []
            for i in range(repeats):
                t_ns = time.perf_counter_ns()
                sha256_hash(secrets.token_bytes(s))
                times_ns.append(time.perf_counter_ns() - t_ns)
                
                if i % 10 == 0:  # Update every 10 iterations
                    progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                    emit_progress('sha256', 'hashing', progress, {
                        'status': f'Hashing {s} bytes ({i+1}/{repeats})',
                        'size': s
                    })
            
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
        emit_progress('sha256', 'complete', 100, {
            'results': results,
            'total_time_ns': total_ns
        })
        
    except Exception as e:
        emit_progress('sha256', 'error', 0, {'error': str(e)})

def run_bb84_with_progress(qubit_counts=[128, 512], repeats=5, error_rate=0.01):
    """Run BB84 with live progress updates"""
    try:
        emit_progress('bb84', 'started', 0, {
            'qubit_counts': qubit_counts,
            'repeats': repeats,
            'error_rate': error_rate
        })
        
        results = {}
        total_tests = len(qubit_counts)
        total_ns = 0
        
        for idx, q in enumerate(qubit_counts):
            emit_progress('bb84', 'simulating', idx * 100 // total_tests, {
                'status': f'Simulating {q} qubits...',
                'qubits': q
            })
            
            times_ns = []
            errs = []
            
            for i in range(repeats):
                t0 = time.perf_counter_ns()
                key, err = bb84_simulate(q, channel_error_rate=error_rate)
                t1 = time.perf_counter_ns()
                times_ns.append(t1 - t0)
                errs.append(err)
                
                progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                emit_progress('bb84', 'simulating', progress, {
                    'status': f'BB84 {q} qubits ({i+1}/{repeats})',
                    'qubits': q,
                    'error': err,
                    'key_length': len(key)
                })
            
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
        emit_progress('bb84', 'complete', 100, {
            'results': results,
            'total_time_ns': total_ns
        })
        
    except Exception as e:
        emit_progress('bb84', 'error', 0, {'error': str(e)})

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

    try:
        socketio.start_background_task(
            run_rsa_with_progress,
            rsa_params["bits"],
            rsa_params["msg_size"],
            rsa_params["repeats"],
        )
        socketio.start_background_task(
            run_ecc_with_progress,
            ecc_params["curve"],
            ecc_params["repeats"],
        )
        socketio.start_background_task(
            run_sha256_with_progress,
            sha256_params["sizes"],
            sha256_params["repeats"],
        )
        socketio.start_background_task(
            run_bb84_with_progress,
            bb84_params["qubit_counts"],
            bb84_params["repeats"],
            bb84_params["error_rate"],
        )
    except Exception as exc:
        safe_emit(
            "error",
            {"message": f"Failed to start benchmarks: {exc}", "source_event": "run_benchmarks"},
            allow_error=False,
        )
        return

    safe_emit('benchmarks_started', {'message': 'All algorithms started with custom parameters'})

@socketio.on('connect')
def handle_connect():
     print('Client connected')
     safe_emit('connected', {'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
     print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)