from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
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

def emit_progress(algorithm, stage, progress, data=None):
    """Helper to emit progress updates"""
    socketio.emit('algorithm_progress', {
        'algorithm': algorithm,
        'stage': stage,
        'progress': progress,
        'data': data,
        'timestamp': time.time()
    })

def run_rsa_with_progress(bits=512, msg_size=32, repeats=2):
    """Run RSA with live progress updates"""
    try:
        emit_progress('rsa', 'started', 0, {'bits': bits, 'msg_size': msg_size})
        
        # Key generation
        emit_progress('rsa', 'keygen', 10, {'status': f'Generating {bits}-bit prime numbers...'})
        time.sleep(0.1)
        t = time.perf_counter()
        pub, priv = rsa_keygen(bits)
        gen_time = time.perf_counter() - t
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
        enc_times = []
        for i in range(repeats):
            t = time.perf_counter()
            chunks = rsa_encrypt_bytes(pub, msg)
            enc_times.append(time.perf_counter() - t)
            emit_progress('rsa', 'encrypt', 50 + (i+1) * 15 // repeats, {
                'status': f'Encryption {i+1}/{repeats}',
                'chunks': len(chunks)
            })
        enc_time = sum(enc_times) / repeats
        
        # Decryption
        emit_progress('rsa', 'decrypt', 70, {'status': 'Decrypting...'})
        dec_times = []
        for i in range(repeats):
            t = time.perf_counter()
            recovered = rsa_decrypt_bytes(priv, chunks)
            dec_times.append(time.perf_counter() - t)
            emit_progress('rsa', 'decrypt', 70 + (i+1) * 20 // repeats, {
                'status': f'Decryption {i+1}/{repeats}'
            })
        dec_time = sum(dec_times) / repeats
        
        # Complete
        emit_progress('rsa', 'complete', 100, {
            'keygen_time': gen_time,
            'encrypt_time': enc_time,
            'decrypt_time': dec_time,
            'total_time': gen_time + enc_time + dec_time
        })
        
    except Exception as e:
        emit_progress('rsa', 'error', 0, {'error': str(e)})

def run_ecc_with_progress(curve_name='secp192r1', repeats=10):
    """Run ECC with live progress updates"""
    try:
        # Select curve (for now only secp192r1 is implemented)
        curve = SECP192_TEST
        emit_progress('ecc', 'started', 0, {'curve': curve.name, 'repeats': repeats})
        
        # Key generation
        emit_progress('ecc', 'keygen', 10, {'status': 'Generating key pairs...'})
        pairs = []
        t = time.perf_counter()
        for i in range(repeats):
            pairs.append(ecc_keygen(curve))
            emit_progress('ecc', 'keygen', 10 + (i+1) * 40 // repeats, {
                'status': f'Generated {i+1}/{repeats} pairs'
            })
        keygen_time = (time.perf_counter() - t) / repeats
        
        # ECDH shared secret
        emit_progress('ecc', 'ecdh', 50, {'status': 'Computing shared secrets...'})
        t = time.perf_counter()
        for i in range(repeats):
            d1, Q1 = pairs[i]
            d2, Q2 = pairs[(i+1) % repeats]
            s1 = ecdh_shared_secret(d1, Q2, curve)
            s2 = ecdh_shared_secret(d2, Q1, curve)
            emit_progress('ecc', 'ecdh', 50 + (i+1) * 45 // repeats, {
                'status': f'ECDH {i+1}/{repeats}',
                'matched': s1 == s2
            })
        shared_time = (time.perf_counter() - t) / repeats
        
        # Complete
        emit_progress('ecc', 'complete', 100, {
            'keygen_time': keygen_time,
            'shared_time': shared_time,
            'total_time': keygen_time * repeats + shared_time * repeats
        })
        
    except Exception as e:
        emit_progress('ecc', 'error', 0, {'error': str(e)})

def run_sha256_with_progress(sizes=[16, 128, 1024], repeats=50):
    """Run SHA-256 with live progress updates"""
    try:
        emit_progress('sha256', 'started', 0, {'sizes': sizes, 'repeats': repeats})
        
        results = {}
        total_tests = len(sizes)
        
        for idx, s in enumerate(sizes):
            emit_progress('sha256', 'hashing', idx * 100 // total_tests, {
                'status': f'Hashing {s} bytes...',
                'size': s
            })
            
            times = []
            for i in range(repeats):
                t = time.perf_counter()
                sha256_hash(secrets.token_bytes(s))
                times.append(time.perf_counter() - t)
                
                if i % 10 == 0:  # Update every 10 iterations
                    progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                    emit_progress('sha256', 'hashing', progress, {
                        'status': f'Hashing {s} bytes ({i+1}/{repeats})',
                        'size': s
                    })
            
            elapsed = sum(times) / repeats
            results[s] = elapsed
        
        # Complete
        emit_progress('sha256', 'complete', 100, {
            'results': {str(k): v for k, v in results.items()},
            'total_time': sum(results.values())
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
        
        for idx, q in enumerate(qubit_counts):
            emit_progress('bb84', 'simulating', idx * 100 // total_tests, {
                'status': f'Simulating {q} qubits...',
                'qubits': q
            })
            
            times = []
            errs = []
            
            for i in range(repeats):
                t0 = time.perf_counter()
                key, err = bb84_simulate(q, channel_error_rate=error_rate)
                t1 = time.perf_counter()
                times.append(t1 - t0)
                errs.append(err)
                
                progress = idx * 100 // total_tests + (i+1) * 100 // (total_tests * repeats)
                emit_progress('bb84', 'simulating', progress, {
                    'status': f'BB84 {q} qubits ({i+1}/{repeats})',
                    'qubits': q,
                    'error': err,
                    'key_length': len(key)
                })
            
            results[q] = {
                'avg_time': statistics.mean(times),
                'avg_error': statistics.mean(errs)
            }
        
        # Complete
        emit_progress('bb84', 'complete', 100, {
            'results': {str(k): v for k, v in results.items()},
            'total_time': sum(r['avg_time'] for r in results.values())
        })
        
    except Exception as e:
        emit_progress('bb84', 'error', 0, {'error': str(e)})

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('run_benchmarks')
def handle_run_benchmarks(params):
    """Run all algorithms in parallel with user-specified parameters"""
    
    # Extract parameters
    rsa_params = params.get('rsa', {})
    ecc_params = params.get('ecc', {})
    sha256_params = params.get('sha256', {})
    bb84_params = params.get('bb84', {})
    
    # Start each algorithm in a separate thread with user parameters
    threads = [
        threading.Thread(
            target=run_rsa_with_progress,
            args=(
                rsa_params.get('bits', 512),
                rsa_params.get('msg_size', 32),
                rsa_params.get('repeats', 2)
            )
        ),
        threading.Thread(
            target=run_ecc_with_progress,
            args=(
                ecc_params.get('curve', 'secp192r1'),
                ecc_params.get('repeats', 10)
            )
        ),
        threading.Thread(
            target=run_sha256_with_progress,
            args=(
                sha256_params.get('sizes', [16, 128, 1024]),
                sha256_params.get('repeats', 50)
            )
        ),
        threading.Thread(
            target=run_bb84_with_progress,
            args=(
                bb84_params.get('qubit_counts', [128, 512]),
                bb84_params.get('repeats', 5),
                bb84_params.get('error_rate', 0.01)
            )
        )
    ]
    
    for thread in threads:
        thread.start()
    
    emit('benchmarks_started', {'message': 'All algorithms started with custom parameters'})

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)