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
    state[algorithm].data = { ...state[algorithm].data, ...algoData };
    
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
    switch(algorithm) {
        case 'rsa':
            if (data.keygen_time) {
                document.getElementById('rsa-keygen').textContent = `${(data.keygen_time * 1000).toFixed(2)} ms`;
            }
            if (data.encrypt_time) {
                document.getElementById('rsa-encrypt').textContent = `${(data.encrypt_time * 1000).toFixed(2)} ms`;
            }
            if (data.decrypt_time) {
                document.getElementById('rsa-decrypt').textContent = `${(data.decrypt_time * 1000).toFixed(2)} ms`;
            }
            if (data.total_time) {
                document.getElementById('rsa-total').textContent = `${(data.total_time * 1000).toFixed(2)} ms`;
            }
            break;
            
        case 'ecc':
            if (data.keygen_time) {
                document.getElementById('ecc-keygen').textContent = `${(data.keygen_time * 1000).toFixed(3)} ms`;
            }
            if (data.shared_time) {
                document.getElementById('ecc-shared').textContent = `${(data.shared_time * 1000).toFixed(3)} ms`;
            }
            if (data.total_time) {
                document.getElementById('ecc-total').textContent = `${(data.total_time * 1000).toFixed(2)} ms`;
            }
            break;
            
        case 'sha256':
            if (data.size) {
                document.getElementById('sha256-size-value').textContent = `${data.size} bytes`;
            }
            if (data.time) {
                document.getElementById('sha256-time').textContent = `${(data.time * 1000000).toFixed(3)} μs`;
            }
            if (data.total_time) {
                document.getElementById('sha256-total').textContent = `${(data.total_time * 1000000).toFixed(2)} μs`;
            }
            break;
            
        case 'bb84':
            if (data.qubit_count) {
                document.getElementById('bb84-qubits').textContent = `${data.qubit_count} qubits`;
            }
            if (data.avg_time) {
                document.getElementById('bb84-time').textContent = `${(data.avg_time * 1000).toFixed(2)} ms`;
            }
            if (data.avg_error !== undefined) {
                document.getElementById('bb84-error-rate').textContent = `${(data.avg_error * 100).toFixed(2)}%`;
            }
            if (data.total_time) {
                document.getElementById('bb84-total').textContent = `${(data.total_time * 1000).toFixed(2)} ms`;
            }
            break;
    }
}

function updateChart(algorithm, data) {
    const canvas = document.getElementById(`${algorithm}-canvas`);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart
    if (charts[algorithm]) {
        charts[algorithm].destroy();
    }
    
    let chartData, chartOptions;
    
    switch(algorithm) {
        case 'rsa':
            chartData = {
                labels: ['Key Gen', 'Encrypt', 'Decrypt'],
                datasets: [{
                    label: 'Time (ms)',
                    data: [
                        (data.keygen_time * 1000).toFixed(2),
                        (data.encrypt_time * 1000).toFixed(2),
                        (data.decrypt_time * 1000).toFixed(2)
                    ],
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
            
        case 'ecc':
            chartData = {
                labels: ['Key Gen', 'Shared Secret'],
                datasets: [{
                    label: 'Time (ms)',
                    data: [
                        (data.keygen_time * 1000).toFixed(3),
                        (data.shared_time * 1000).toFixed(3)
                    ],
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
            
        case 'sha256':
            chartData = {
                labels: [`${data.size} bytes`],
                datasets: [{
                    label: 'Time (μs)',
                    data: [(data.time * 1000000).toFixed(3)],
                    backgroundColor: 'rgba(245, 158, 11, 0.7)',
                    borderColor: 'rgba(245, 158, 11, 1)',
                    borderWidth: 2
                }]
            };
            break;
            
        case 'bb84':
            chartData = {
                labels: [`${data.qubit_count} qubits`],
                datasets: [{
                    label: 'Time (ms)',
                    data: [(data.avg_time * 1000).toFixed(2)],
                    backgroundColor: 'rgba(236, 72, 153, 0.7)',
                    borderColor: 'rgba(236, 72, 153, 1)',
                    borderWidth: 2
                }]
            };
            break;
    }
    
    chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
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
    
    const rsaTotal = state.rsa.data.total_time * 1000 || 0;
    const eccTotal = state.ecc.data.total_time * 1000 || 0;
    const sha256Total = state.sha256.data.total_time * 1000000 || 0; // to μs
    const bb84Total = state.bb84.data.total_time * 1000 || 0;
    
    charts.comparison = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['RSA (ms)', 'ECC (ms)', 'SHA-256 (μs)', 'BB84 (ms)'],
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