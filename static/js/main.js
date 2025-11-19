const socket = io();

// State management
const state = {
    rsa: { progress: 0, status: 'waiting', data: {} },
    ecc: { progress: 0, status: 'waiting', data: {} },
    sha256: { progress: 0, status: 'waiting', data: {} },
    bb84: { progress: 0, status: 'waiting', data: {} }
};

// Chart instances
let charts = {
    rsa: null,
    ecc: null,
    sha256: null,
    bb84: null,
    comparison: null
};

// DOM Elements
const runBtn = document.getElementById('runBtn');
const resetBtn = document.getElementById('resetBtn');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');

// Formatting helpers
const toMsFromSeconds = (seconds) => (typeof seconds === 'number' ? seconds * 1000 : 0);
const toMsFromNs = (ns) => (typeof ns === 'number' ? ns / 1_000_000 : 0);
const toUsFromNs = (ns) => (typeof ns === 'number' ? ns / 1000 : 0);

const formatMsFromSeconds = (seconds, digits = 3) =>
    typeof seconds === 'number' ? `${toMsFromSeconds(seconds).toFixed(digits)} ms` : '--';

const formatMsFromNs = (ns, digits = 3) =>
    typeof ns === 'number' ? `${toMsFromNs(ns).toFixed(digits)} ms` : '--';

const formatUsFromNs = (ns, digits = 3) =>
    typeof ns === 'number' ? `${toUsFromNs(ns).toFixed(digits)} μs` : '--';

// Get configuration parameters
function getParameters() {
    // RSA Parameters
    const rsaBits = parseInt(document.getElementById('rsa-bits').value);
    const rsaMsgSize = parseInt(document.getElementById('rsa-msgsize').value);
    const rsaRepeats = parseInt(document.getElementById('rsa-repeats').value);

    // ECC Parameters
    const eccCurve = document.getElementById('ecc-curve').value;
    const eccRepeats = parseInt(document.getElementById('ecc-repeats').value);

    // SHA-256 Parameters - Get selected radio button
    const sha256SizeRadio = document.querySelector('input[name="sha256-size"]:checked');
    const sha256Size = sha256SizeRadio ? parseInt(sha256SizeRadio.value) : 128;
    const sha256Repeats = parseInt(document.getElementById('sha256-repeats').value);

    // BB84 Parameters - Get selected radio button
    const bb84QubitRadio = document.querySelector('input[name="bb84-qubit"]:checked');
    const bb84Qubit = bb84QubitRadio ? parseInt(bb84QubitRadio.value) : 128;
    const bb84Repeats = parseInt(document.getElementById('bb84-repeats').value);
    const bb84Error = parseFloat(document.getElementById('bb84-error').value);

    return {
        rsa: {
            bits: rsaBits,
            msg_size: rsaMsgSize,
            repeats: rsaRepeats
        },
        ecc: {
            curve: eccCurve,
            repeats: eccRepeats
        },
        sha256: {
            size: sha256Size,
            repeats: sha256Repeats
        },
        bb84: {
            qubit_count: bb84Qubit,
            repeats: bb84Repeats,
            error_rate: bb84Error
        }
    };
}

// Socket event handlers
socket.on('connect', () => {
    console.log('Connected to server');
    updateStatus('connected', 'Connected');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateStatus('disconnected', 'Disconnected');
});

socket.on('algorithm_progress', (data) => {
    updateAlgorithm(data);
});

socket.on('benchmarks_started', (data) => {
    console.log('Benchmarks started');
    runBtn.disabled = true;
    updateStatus('running', 'Running...');
});

// Button handlers
runBtn.addEventListener('click', () => {
    resetAll();
    const params = getParameters();
    state.sha256.data.selectedSize = params.sha256.size;
    state.bb84.data.selectedQubit = params.bb84.qubit_count;
    console.log('Starting benchmarks with parameters:', params);
    socket.emit('run_benchmarks', params);
    runBtn.disabled = true;
});

resetBtn.addEventListener('click', () => {
    resetAll();
    runBtn.disabled = false;
});

// Update functions
function updateStatus(type, text) {
    statusText.textContent = text;
    statusDot.className = `status-dot ${type}`;
}

function updateAlgorithm(data) {
    const { algorithm, stage, progress, data: algoData } = data;
    
    state[algorithm].progress = progress;
    state[algorithm].status = stage;
    state[algorithm].data = { ...state[algorithm].data, ...(algoData || {}) };
    
    // Update progress bar
    const progressFill = document.getElementById(`${algorithm}-progress`);
    const progressText = document.getElementById(`${algorithm}-percentage`);
    progressFill.style.width = `${progress}%`;
    progressText.textContent = `${Math.round(progress)}%`;
    
    // Update stage info
    const stageInfo = document.getElementById(`${algorithm}-stage`);
    if (algoData && algoData.status) {
        stageInfo.textContent = algoData.status;
    }
    
    // Update card state
    const card = document.getElementById(`${algorithm}-card`);
    card.classList.remove('waiting', 'running', 'complete', 'error');
    
    if (stage === 'error') {
        card.classList.add('error');
        stageInfo.textContent = `Error: ${algoData.error}`;
    } else if (progress === 100) {
        card.classList.add('complete');
        updateMetrics(algorithm, algoData);
        updateChart(algorithm, algoData);
        updateComparisonChart();
    } else if (progress > 0) {
        card.classList.add('running');
    }
    
    // Check if all complete
    checkAllComplete();
}

function updateMetrics(algorithm, data) {
    switch (algorithm) {
        case 'rsa': {
            const keygen = data.keygen_stats;
            if (keygen && typeof keygen.avg_ns === 'number') {
                const base = formatMsFromNs(keygen.avg_ns, 2);
                const std = keygen.std_ns ? formatMsFromNs(keygen.std_ns, 2) : null;
                document.getElementById('rsa-keygen').textContent = std ? `${base} ± ${std}` : base;
            }

            const encrypt = data.encrypt_stats;
            if (encrypt && typeof encrypt.avg_ns === 'number') {
                const base = formatUsFromNs(encrypt.avg_ns, 2);
                const std = encrypt.std_ns ? formatUsFromNs(encrypt.std_ns, 2) : null;
                document.getElementById('rsa-encrypt').textContent = std ? `${base} ± ${std}` : base;
            }

            const decrypt = data.decrypt_stats;
            if (decrypt && typeof decrypt.avg_ns === 'number') {
                const base = formatUsFromNs(decrypt.avg_ns, 2);
                const std = decrypt.std_ns ? formatUsFromNs(decrypt.std_ns, 2) : null;
                document.getElementById('rsa-decrypt').textContent = std ? `${base} ± ${std}` : base;
            }

            if (typeof data.total_time_ns === 'number') {
                document.getElementById('rsa-total').textContent = `${toMsFromNs(data.total_time_ns).toFixed(2)} ms`;
            }
            break;
        }

        case 'ecc': {
            const keygen = data.keygen_stats;
            if (keygen && typeof keygen.avg_ns === 'number') {
                const base = formatMsFromNs(keygen.avg_ns, 3);
                const std = keygen.std_ns ? formatMsFromNs(keygen.std_ns, 3) : null;
                document.getElementById('ecc-keygen').textContent = std ? `${base} ± ${std}` : base;
            }

            const shared = data.shared_stats;
            if (shared && typeof shared.avg_ns === 'number') {
                const base = formatMsFromNs(shared.avg_ns, 3);
                const std = shared.std_ns ? formatMsFromNs(shared.std_ns, 3) : null;
                document.getElementById('ecc-shared').textContent = std ? `${base} ± ${std}` : base;
            }

            if (typeof data.total_time_ns === 'number') {
                document.getElementById('ecc-total').textContent = `${toMsFromNs(data.total_time_ns).toFixed(2)} ms`;
            }
            break;
        }

        case 'sha256': {
            const resultEntries = data.results ? Object.entries(data.results) : [];
            const preferredKey = state.sha256.data.selectedSize !== undefined
                ? String(state.sha256.data.selectedSize)
                : data.size !== undefined
                    ? String(data.size)
                    : (resultEntries.length ? resultEntries[0][0] : undefined);
            const activeEntry = resultEntries.find(([key]) => key === preferredKey) || resultEntries[0];

            if (activeEntry) {
                const activeKey = Number(activeEntry[0]);
                if (Number.isFinite(activeKey)) {
                    document.getElementById('sha256-size-value').textContent = `${activeKey} bytes`;
                }

                const stats = activeEntry[1];
                if (stats && typeof stats.avg_ns === 'number') {
                    const avgUs = formatUsFromNs(stats.avg_ns, 3);
                    const stdUs = stats.std_ns ? formatUsFromNs(stats.std_ns, 3) : null;
                    document.getElementById('sha256-time').textContent = stdUs ? `${avgUs} ± ${stdUs}` : avgUs;
                }
            }

            if (typeof data.total_time_ns === 'number') {
                document.getElementById('sha256-total').textContent = `${toMsFromNs(data.total_time_ns).toFixed(2)} ms`;
            }
            break;
        }

        case 'bb84': {
            const resultEntries = data.results ? Object.entries(data.results) : [];
            if (resultEntries.length) {
                const preferredKey = state.bb84.data.selectedQubit !== undefined
                    ? String(state.bb84.data.selectedQubit)
                    : data.qubits !== undefined
                        ? String(data.qubits)
                        : resultEntries[0][0];
                const activeEntry = resultEntries.find(([key]) => key === preferredKey) || resultEntries[0];

                if (activeEntry) {
                    const qubits = Number(activeEntry[0]);
                    document.getElementById('bb84-qubits').textContent = Number.isFinite(qubits)
                        ? `${qubits}`
                        : activeEntry[0];

                    const stats = activeEntry[1] || {};
                    if (typeof stats.avg_ns === 'number') {
                        const avgMs = formatMsFromNs(stats.avg_ns, 3);
                        const stdMs = stats.std_ns ? formatMsFromNs(stats.std_ns, 3) : null;
                        document.getElementById('bb84-time').textContent = stdMs ? `${avgMs} ± ${stdMs}` : avgMs;
                    }

                    if (typeof stats.avg_error === 'number') {
                        document.getElementById('bb84-error-rate').textContent = `${(stats.avg_error * 100).toFixed(2)}%`;
                    }
                }
            }

            if (typeof data.total_time_ns === 'number') {
                document.getElementById('bb84-total').textContent = `${toMsFromNs(data.total_time_ns).toFixed(2)} ms`;
            }
            break;
        }

        default:
            break;
    }
}

function updateChart(algorithm, data) {
    const canvas = document.getElementById(`${algorithm}-canvas`);
    if (!canvas) {
        return;
    }

    const ctx = canvas.getContext('2d');

    if (charts[algorithm]) {
        charts[algorithm].destroy();
    }

    let chartData = null;

    switch (algorithm) {
        case 'rsa': {
            const keygenMs = data.keygen_stats?.avg_ns ? toMsFromNs(data.keygen_stats.avg_ns) : 0;
            const encryptMs = data.encrypt_stats?.avg_ns ? toMsFromNs(data.encrypt_stats.avg_ns) : 0;
            const decryptMs = data.decrypt_stats?.avg_ns ? toMsFromNs(data.decrypt_stats.avg_ns) : 0;

            chartData = {
                labels: ['Key Gen', 'Encrypt', 'Decrypt'],
                datasets: [{
                    label: 'Time (ms)',
                    data: [keygenMs, encryptMs, decryptMs],
                    backgroundColor: [
                        'rgba(99, 102, 241, 0.7)',
                        'rgba(139, 92, 246, 0.7)',
                        'rgba(168, 85, 247, 0.7)'
                    ],
                    borderColor: [
                        'rgba(99, 102, 241, 1)',
                        'rgba(139, 92, 246, 1)',
                        'rgba(168, 85, 247, 1)'
                    ],
                    borderWidth: 2
                }]
            };
            break;
        }

        case 'ecc': {
            const keygenMs = data.keygen_stats?.avg_ns ? toMsFromNs(data.keygen_stats.avg_ns) : 0;
            const sharedMs = data.shared_stats?.avg_ns ? toMsFromNs(data.shared_stats.avg_ns) : 0;

            chartData = {
                labels: ['Key Gen', 'Shared Secret'],
                datasets: [{
                    label: 'Time (ms)',
                    data: [keygenMs, sharedMs],
                    backgroundColor: [
                        'rgba(16, 185, 129, 0.7)',
                        'rgba(5, 150, 105, 0.7)'
                    ],
                    borderColor: [
                        'rgba(16, 185, 129, 1)',
                        'rgba(5, 150, 105, 1)'
                    ],
                    borderWidth: 2
                }]
            };
            break;
        }

        case 'sha256': {
            const resultEntries = data.results ? Object.entries(data.results) : [];
            if (!resultEntries.length) {
                break;
            }

            const preferredKey = state.sha256.data.selectedSize !== undefined
                ? String(state.sha256.data.selectedSize)
                : data.size !== undefined
                    ? String(data.size)
                    : resultEntries[0][0];
            const activeEntry = resultEntries.find(([key]) => key === preferredKey) || resultEntries[0];
            const selectedLabel = activeEntry ? activeEntry[0] : resultEntries[0][0];
            const avgNs = activeEntry?.[1]?.avg_ns ?? null;

            chartData = {
                labels: [`${selectedLabel} bytes`],
                datasets: [{
                    label: 'Time (μs)',
                    data: [avgNs !== null ? toUsFromNs(avgNs) : 0],
                    backgroundColor: 'rgba(245, 158, 11, 0.7)',
                    borderColor: 'rgba(245, 158, 11, 1)',
                    borderWidth: 2
                }]
            };
            break;
        }

        case 'bb84': {
            const resultEntries = data.results ? Object.entries(data.results) : [];
            if (!resultEntries.length) {
                break;
            }

            const labels = resultEntries.map(([key]) => `${key} qubits`);
            const dataPoints = resultEntries.map(([, stats]) => stats?.avg_ns ? toMsFromNs(stats.avg_ns) : 0);

            chartData = {
                labels,
                datasets: [{
                    label: 'Time (ms)',
                    data: dataPoints,
                    backgroundColor: dataPoints.map((_, i) =>
                        `rgba(${Math.max(200, 236 - i * 12)}, ${Math.min(255, 72 + i * 8)}, ${Math.max(120, 153 - i * 10)}, 0.7)`
                    ),
                    borderColor: dataPoints.map((_, i) =>
                        `rgba(${Math.max(200, 236 - i * 12)}, ${Math.min(255, 72 + i * 8)}, ${Math.max(120, 153 - i * 10)}, 1)`
                    ),
                    borderWidth: 2
                }]
            };
            break;
        }

        default:
            chartData = null;
    }

    if (!chartData) {
        return;
    }

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(148, 163, 184, 0.1)'
                },
                ticks: {
                    color: '#94a3b8'
                }
            },
            x: {
                grid: {
                    color: 'rgba(148, 163, 184, 0.1)'
                },
                ticks: {
                    color: '#94a3b8'
                }
            }
        }
    };

    charts[algorithm] = new Chart(ctx, {
        type: 'bar',
        data: chartData,
        options: chartOptions
    });
}

function updateComparisonChart() {
    // Only update if all algorithms are complete
    const allComplete = Object.values(state).every(s => s.progress === 100);
    if (!allComplete) return;
    
    const canvas = document.getElementById('comparisonChart');
    const ctx = canvas.getContext('2d');
    
    if (charts.comparison) {
        charts.comparison.destroy();
    }
    
    const rsaTotal = state.rsa.data.total_time_ns
        ? toMsFromNs(state.rsa.data.total_time_ns)
        : toMsFromSeconds(state.rsa.data.total_time);
    const eccTotal = state.ecc.data.total_time_ns
        ? toMsFromNs(state.ecc.data.total_time_ns)
        : toMsFromSeconds(state.ecc.data.total_time);
    const sha256Total = state.sha256.data.total_time_ns
        ? toMsFromNs(state.sha256.data.total_time_ns)
        : toMsFromSeconds(state.sha256.data.total_time);
    const bb84Total = state.bb84.data.total_time_ns
        ? toMsFromNs(state.bb84.data.total_time_ns)
        : toMsFromSeconds(state.bb84.data.total_time);
    
    charts.comparison = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['RSA (ms)', 'ECC (ms)', 'SHA-256 (ms)', 'BB84 (ms)'],
            datasets: [{
                label: 'Total Execution Time',
                data: [rsaTotal, eccTotal, sha256Total, bb84Total],
                backgroundColor: [
                    'rgba(99, 102, 241, 0.7)',
                    'rgba(16, 185, 129, 0.7)',
                    'rgba(245, 158, 11, 0.7)',
                    'rgba(236, 72, 153, 0.7)'
                ],
                borderColor: [
                    'rgba(99, 102, 241, 1)',
                    'rgba(16, 185, 129, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(236, 72, 153, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Algorithm Performance Comparison',
                    color: '#f1f5f9',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            }
        }
    });
}

function checkAllComplete() {
    const allComplete = Object.values(state).every(s => s.progress === 100);
    if (allComplete) {
        updateStatus('complete', 'All Complete!');
        runBtn.disabled = false;
    }
}

function resetAll() {
    // Reset state
    Object.keys(state).forEach(key => {
        state[key] = { progress: 0, status: 'waiting', data: {} };
    });
    
    // Reset UI
    ['rsa', 'ecc', 'sha256', 'bb84'].forEach(algo => {
        document.getElementById(`${algo}-progress`).style.width = '0%';
        document.getElementById(`${algo}-percentage`).textContent = '0%';
        document.getElementById(`${algo}-stage`).textContent = 'Waiting to start...';
        document.getElementById(`${algo}-card`).classList.remove('running', 'complete', 'error');
        
        // Reset metrics
        const metrics = document.querySelectorAll(`#${algo}-metrics .metric-value`);
        metrics.forEach(m => m.textContent = '--');
        
        // Destroy charts
        if (charts[algo]) {
            charts[algo].destroy();
            charts[algo] = null;
        }
    });
    
    // Destroy comparison chart
    if (charts.comparison) {
        charts.comparison.destroy();
        charts.comparison = null;
    }
    
    updateStatus('connected', 'Ready');
}

// Additional functions for RSA and ECC providers
function get_rsa_provider(prefer_pycryptodome = true) {
    if (prefer_pycryptodome && HAS_PYCRYPTODOME) {
        return PyCryptodomeRSAImpl.generate_key();
    }
    return RSAImpl.generate_key();
}

function get_ecc_provider(prefer_crypto = true) {
    if (prefer_crypto && HAS_CRYPTOGRAPHY) {
        return CryptographyECCImpl();
    }
    return ECCImpl(SECP192_TEST);
}

function benchmark_cryptography_rsa_oaep(message_size = 128, key_size = 2048) {
    if (!HAS_CRYPTOGRAPHY) {
        throw new RuntimeError("cryptography library not available");
    }
    const private_key = crypto_rsa.generate_private_key({ public_exponent: 65537, key_size: key_size });
    const public_key = private_key.public_key();
    const message = secrets.token_bytes(message_size);
    let start = performance.now();
    const ciphertext = public_key.encrypt(
        message,
        crypto_padding.OAEP({
            mgf: crypto_padding.MGF1({ algorithm: crypto_hashes.SHA256() }),
            algorithm: crypto_hashes.SHA256(),
            label: null
        })
    );
    const enc_duration = performance.now() - start;
    start = performance.now();
    const plaintext = private_key.decrypt(
        ciphertext,
        crypto_padding.OAEP({
            mgf: crypto_padding.MGF1({ algorithm: crypto_hashes.SHA256() }),
            algorithm: crypto_hashes.SHA256(),
            label: null
        })
    );
    const dec_duration = performance.now() - start;
    return {
        key_size: key_size,
        message_size: message_size,
        encrypt_s: enc_duration,
        decrypt_s: dec_duration,
        success: plaintext === message
    };
}

function benchmark_cryptography_ecc_secp256r1(message_size = 32) {
    if (!HAS_CRYPTOGRAPHY) {
        throw new RuntimeError("cryptography library not available");
    }
    const private_key = crypto_ec.generate_private_key(crypto_ec.SECP256R1());
    const peer_key = crypto_ec.generate_private_key(crypto_ec.SECP256R1());
    const message = secrets.token_bytes(message_size);
    let start = performance.now();
    const signature = private_key.sign(message, crypto_ec.ECDSA(crypto_hashes.SHA256()));
    const sign_duration = performance.now() - start;
    start = performance.now();
    peer_key.public_key().verify(signature, message, crypto_ec.ECDSA(crypto_hashes.SHA256()));
    const verify_duration = performance.now() - start;
    const shared_secret = private_key.exchange(crypto_ec.ECDH(), peer_key.public_key());
    return {
        sign_s: sign_duration,
        verify_s: verify_duration,
        secret_len: shared_secret.byteLength
    };
}