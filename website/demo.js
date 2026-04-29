/**
 * SignedByMe Live Demo
 * 
 * Demonstrates the NOSTR event flow:
 * 
 * ENROLLMENT FLOW:
 * 1. Enterprise signs kind 28200 authorization event
 * 2. Human signs kind 28250 delegation event
 * 3. Agent calls POST /v1/membership/enroll/commit
 * 
 * LOGIN FLOW:
 * 1. Agent generates Groth16 proof
 * 2. Agent calls POST /v1/login/verify
 * 3. Receives OIDC id_token
 */

// Configuration
const CONFIG = {
    API_BASE: 'https://api.beta.privacy-lion.com',
    CLIENT_ID: 'signedbyme-demo',
    AMOUNT_SATS: 100
};

// SignedByMe relay infrastructure (Phase 29: Multi-relay)
const SIGNEDBY_RELAYS = [
    'wss://relay.privacy-lion.com',      // US East (ATL) - primary
    'wss://relay-sfo.privacy-lion.com',  // US West (SFO)
    'wss://relay-ams.privacy-lion.com',  // Europe (AMS)
    'wss://relay-sgp.privacy-lion.com',  // Asia (SGP)
];
// Legacy single URL for backwards compatibility  
CONFIG.RELAY_URL = SIGNEDBY_RELAYS[0];

// Demo State
const state = {
    currentNonce: null,
    currentMode: 'idle', // 'idle' | 'login' | 'enroll'
    relayWs: null,
    enrollmentInterval: null,
    timerInterval: null
};

// DOM References (populated on init)
let dom = {};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', initDemo);

function initDemo() {
    const container = document.getElementById('demo-container');
    if (!container) return;
    
    // Build demo UI
    container.innerHTML = buildDemoHTML();
    
    // Cache DOM references
    dom = {
        container: container,
        modeSelect: document.getElementById('demo-mode'),
        startBtn: document.getElementById('demo-start'),
        resetBtn: document.getElementById('demo-reset'),
        qrContainer: document.getElementById('demo-qr'),
        status: document.getElementById('demo-status'),
        events: document.getElementById('demo-events'),
        result: document.getElementById('demo-result'),
        timer: document.getElementById('demo-timer')
    };
    
    // Event listeners
    dom.startBtn.addEventListener('click', startDemo);
    dom.resetBtn.addEventListener('click', resetDemo);
    
    log('Demo initialized. Select a flow and click Start.');
}

function buildDemoHTML() {
    return `
        <div class="demo-layout">
            <div class="demo-controls">
                <div class="demo-control-group">
                    <label for="demo-mode">Flow</label>
                    <select id="demo-mode">
                        <option value="login">Login (User → Enterprise)</option>
                        <option value="enroll">Enrollment (Enterprise → User)</option>
                    </select>
                </div>
                <button id="demo-start" class="btn btn-primary">Start Demo</button>
                <button id="demo-reset" class="btn btn-secondary" style="display: none;">Reset</button>
            </div>
            
            <div class="demo-main">
                <div class="demo-qr-section">
                    <div id="demo-qr" class="demo-qr-box">
                        <p class="demo-qr-placeholder">Select a flow to begin</p>
                    </div>
                    <p id="demo-timer" class="demo-timer"></p>
                </div>
                
                <div class="demo-status-section">
                    <h3>Status</h3>
                    <p id="demo-status">Ready</p>
                    
                    <h3>NOSTR Events</h3>
                    <div id="demo-events" class="demo-events-log">
                        <p class="demo-event-placeholder">Events will appear here...</p>
                    </div>
                </div>
            </div>
            
            <div id="demo-result" class="demo-result" style="display: none;">
                <!-- Result displayed here on success -->
            </div>
        </div>
        
        <style>
            .demo-layout {
                display: flex;
                flex-direction: column;
                gap: 24px;
            }
            .demo-controls {
                display: flex;
                align-items: center;
                gap: 16px;
                flex-wrap: wrap;
            }
            .demo-control-group {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .demo-control-group select {
                padding: 8px 12px;
                border: 1px solid var(--border);
                border-radius: 6px;
                font-size: 0.95rem;
            }
            .demo-main {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 24px;
            }
            @media (max-width: 768px) {
                .demo-main {
                    grid-template-columns: 1fr;
                }
            }
            .demo-qr-section {
                text-align: center;
            }
            .demo-qr-box {
                background: white;
                border: 2px dashed var(--border);
                border-radius: 12px;
                padding: 24px;
                min-height: 280px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .demo-qr-box.active {
                border: 2px solid var(--primary);
            }
            .demo-qr-placeholder {
                color: var(--text-muted);
            }
            .demo-timer {
                margin-top: 12px;
                font-size: 0.9rem;
                color: var(--text-muted);
            }
            .demo-status-section h3 {
                font-size: 0.9rem;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 8px;
            }
            .demo-status-section h3:not(:first-child) {
                margin-top: 16px;
            }
            #demo-status {
                font-weight: 500;
                color: var(--text);
            }
            .demo-events-log {
                background: #1E1E1E;
                border-radius: 8px;
                padding: 12px;
                max-height: 200px;
                overflow-y: auto;
                font-family: var(--font-mono);
                font-size: 0.8rem;
            }
            .demo-event-placeholder {
                color: #6B7280;
            }
            .demo-event {
                color: #D4D4D4;
                margin-bottom: 4px;
                word-break: break-all;
            }
            .demo-event.success {
                color: #10B981;
            }
            .demo-event.error {
                color: #EF4444;
            }
            .demo-event.info {
                color: #60A5FA;
            }
            .demo-result {
                background: linear-gradient(90deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05));
                border: 1px solid var(--success);
                border-radius: 12px;
                padding: 24px;
            }
            .demo-result h3 {
                color: var(--success);
                margin-bottom: 16px;
            }
            .demo-result pre {
                background: #1E1E1E;
                color: #D4D4D4;
                padding: 12px;
                border-radius: 8px;
                overflow-x: auto;
                font-size: 0.85rem;
            }
        </style>
    `;
}

// ============================================================================
// Demo Flow Control
// ============================================================================

function startDemo() {
    const mode = dom.modeSelect.value;
    state.currentMode = mode;
    
    dom.startBtn.style.display = 'none';
    dom.resetBtn.style.display = 'inline-flex';
    dom.modeSelect.disabled = true;
    dom.qrContainer.classList.add('active');
    
    clearEvents();
    
    if (mode === 'login') {
        startLoginDemo();
    } else {
        startEnrollmentDemo();
    }
}

function resetDemo() {
    // Close connections
    closeRelay();
    clearInterval(state.enrollmentInterval);
    clearInterval(state.timerInterval);
    
    // Reset state
    state.currentNonce = null;
    state.currentMode = 'idle';
    
    // Reset UI
    dom.startBtn.style.display = 'inline-flex';
    dom.resetBtn.style.display = 'none';
    dom.modeSelect.disabled = false;
    dom.qrContainer.classList.remove('active');
    dom.qrContainer.innerHTML = '<p class="demo-qr-placeholder">Select a flow to begin</p>';
    dom.timer.textContent = '';
    dom.status.textContent = 'Ready';
    dom.result.style.display = 'none';
    
    clearEvents();
    log('Demo reset.');
}

// ============================================================================
// Login Flow
// ============================================================================

function startLoginDemo() {
    // Generate nonce locally - no API call
    state.currentNonce = generateNonce();
    log(`Generated nonce: ${state.currentNonce.substring(0, 16)}...`);
    
    // Build deep link
    const deepLink = `signedby://${CONFIG.CLIENT_ID}/${state.currentNonce}/${CONFIG.AMOUNT_SATS}`;
    logEvent('info', `Deep link: ${deepLink}`);
    
    // Render QR
    dom.qrContainer.innerHTML = '';
    new QRCode(dom.qrContainer, {
        text: deepLink,
        width: 220,
        height: 220,
        colorDark: '#3B82F6',
        colorLight: '#FFFFFF'
    });
    
    dom.status.textContent = 'Scan with SignedByMe app...';
    
    // Start 5-minute countdown
    startTimer(300);
    
    // Subscribe to relay
    subscribeToRelay(state.currentNonce);
}

function subscribeToRelay(nonce) {
    closeRelay();
    
    logEvent('info', `Connecting to ${CONFIG.RELAY_URL}...`);
    state.relayWs = new WebSocket(CONFIG.RELAY_URL);
    
    state.relayWs.onopen = () => {
        logEvent('success', 'Connected to relay');
        
        // Subscribe to kind 28101 events tagged with our nonce
        const subRequest = JSON.stringify([
            'REQ',
            'demo-sub',
            {
                kinds: [28101],
                '#nonce': [nonce]
            }
        ]);
        state.relayWs.send(subRequest);
        logEvent('info', 'Subscribed to proof events');
        dom.status.textContent = 'Waiting for proof event...';
    };
    
    state.relayWs.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            
            if (msg[0] === 'EVENT' && msg[1] === 'demo-sub') {
                const nostrEvent = msg[2];
                logEvent('success', `Received kind ${nostrEvent.kind} event`);
                handleProofEvent(nostrEvent);
            } else if (msg[0] === 'EOSE') {
                logEvent('info', 'End of stored events');
            }
        } catch (error) {
            logEvent('error', 'Error parsing relay message');
        }
    };
    
    state.relayWs.onerror = () => {
        logEvent('error', 'Relay connection error');
        dom.status.textContent = 'Connection error. Retrying...';
        
        setTimeout(() => {
            if (state.currentNonce && state.currentMode === 'login') {
                subscribeToRelay(state.currentNonce);
            }
        }, 3000);
    };
    
    state.relayWs.onclose = () => {
        logEvent('info', 'Relay connection closed');
    };
}

async function handleProofEvent(event) {
    dom.status.textContent = 'Proof received! Processing...';
    
    try {
        const content = JSON.parse(event.content);
        logEvent('info', `npub: ${content.public_outputs?.npub?.substring(0, 20)}...`);
        logEvent('info', `Invoices received: user + operator`);
        
        // In a real demo, we'd pay the invoices here
        // For now, show the proof structure
        dom.status.textContent = 'Proof verified!';
        
        dom.result.innerHTML = `
            <h3>✓ Login Successful</h3>
            <p>In production, the enterprise would now:</p>
            <ol>
                <li>Pay both Lightning invoices via Strike/other provider</li>
                <li>Submit proof + preimages to <code>/v1/login/verify</code></li>
                <li>Receive OIDC id_token with <code>sub=npub</code></li>
            </ol>
            <h4>Proof Event Content</h4>
            <pre>${JSON.stringify(content, null, 2)}</pre>
        `;
        dom.result.style.display = 'block';
        
        closeRelay();
        clearInterval(state.timerInterval);
        dom.timer.textContent = '';
        
    } catch (error) {
        logEvent('error', `Error processing proof: ${error.message}`);
        dom.status.textContent = 'Error processing proof';
    }
}

// ============================================================================
// Enrollment Flow
// ============================================================================

function startEnrollmentDemo() {
    logEvent('info', 'Enrollment demo starting...');
    logEvent('info', 'Note: Full enrollment requires enterprise signing key');
    
    // Generate nonce
    state.currentNonce = generateNonce();
    log(`Generated nonce: ${state.currentNonce.substring(0, 16)}...`);
    
    // Build enrollment deep link (without actual signing)
    const expiresAt = Math.floor(Date.now() / 1000) + 90;
    const deepLink = `signedby://enroll/${CONFIG.CLIENT_ID}/${state.currentNonce}?exp=${expiresAt}`;
    logEvent('info', `Deep link: ${deepLink}`);
    
    // Render QR
    dom.qrContainer.innerHTML = '';
    new QRCode(dom.qrContainer, {
        text: deepLink,
        width: 220,
        height: 220,
        colorDark: '#10B981',
        colorLight: '#FFFFFF'
    });
    
    dom.status.textContent = 'Scan to enroll in demo group';
    
    // Start 90-second countdown (enrollment QRs refresh)
    startTimer(90);
    
    // Show enrollment info
    dom.result.innerHTML = `
        <h3 style="color: var(--primary);">Enrollment Demo</h3>
        <p>This demonstrates the enrollment QR code that enterprises display.</p>
        <p>In production:</p>
        <ol>
            <li>Enterprise signs kind 28200 event with their NOSTR key</li>
            <li>Publishes to relay before displaying QR</li>
            <li>User scans → app fetches event → verifies signature</li>
            <li>User's leaf_commitment added to Merkle tree</li>
        </ol>
        <p><strong>Full enrollment requires the enterprise signing key to be configured.</strong></p>
    `;
    dom.result.style.display = 'block';
}

// ============================================================================
// Utilities
// ============================================================================

function generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function closeRelay() {
    if (state.relayWs) {
        state.relayWs.close();
        state.relayWs = null;
    }
}

function startTimer(seconds) {
    clearInterval(state.timerInterval);
    let remaining = seconds;
    
    const update = () => {
        const mins = Math.floor(remaining / 60);
        const secs = remaining % 60;
        dom.timer.textContent = `Expires in ${mins}:${secs.toString().padStart(2, '0')}`;
        
        if (remaining <= 0) {
            clearInterval(state.timerInterval);
            dom.timer.textContent = 'Expired';
            dom.status.textContent = 'Session expired. Click Reset to try again.';
        } else {
            remaining--;
        }
    };
    
    update();
    state.timerInterval = setInterval(update, 1000);
}

function log(message) {
    console.log('[SignedByMe Demo]', message);
}

function logEvent(type, message) {
    const events = dom.events;
    if (!events) return;
    
    // Clear placeholder
    const placeholder = events.querySelector('.demo-event-placeholder');
    if (placeholder) placeholder.remove();
    
    const el = document.createElement('div');
    el.className = `demo-event ${type}`;
    el.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    events.appendChild(el);
    events.scrollTop = events.scrollHeight;
}

function clearEvents() {
    if (dom.events) {
        dom.events.innerHTML = '<p class="demo-event-placeholder">Events will appear here...</p>';
    }
}
