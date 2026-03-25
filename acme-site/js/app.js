/**
 * Acme Corp SignedByMe Integration
 * 
 * Two flows:
 * 
 * LOGIN FLOW:
 * 1. Generate nonce locally (no server call)
 * 2. Display QR code with deep link: signedby://{client_id}/{nonce}/{amount_sats}
 * 3. Subscribe to NOSTR relay for kind 28101 proof events (#n tag)
 * 4. On proof event: pay invoices via Strike, submit to /v1/login/verify
 * 5. Display id_token on success
 * 
 * ENROLLMENT FLOW (Phase 26.9):
 * 1. Generate nonce locally (no server call)
 * 2. Sign and publish kind 28200 event to relay
 * 3. Display QR code with deep link: signedby://enroll/{client_id}/{nonce}?exp={unix_timestamp_90s}
 * 4. Regenerate every 90 seconds
 */

// Configuration
const API_BASE = 'https://api.beta.privacy-lion.com';
const RELAY_URL = 'wss://relay.privacy-lion.com';
const CLIENT_ID = 'acme';
const AMOUNT_SATS = 100;

// Acme Enterprise NOSTR Keys (Phase 26.9)
// Public key published at https://acme.beta.privacy-lion.com/.well-known/nostr.json
const ACME_PUBKEY_HEX = 'f1ff989f13592f68206bc42b9b67fae5c5390e77858afc0e369dfd6d2b2cb7d7';
// Private key - nsec (bech32 format). Retrieved from Bitwarden "Acme Enterprise NOSTR Private Key"
const ACME_PRIVKEY_NSEC = '%%ACME_PRIVKEY_NSEC%%'; // TODO: Scott to fill in

// Strike API - signedby-demo key (dev/test only - temporary scaffolding)
const STRIKE_API_KEY = '4F683B6BDAD5E8ED8A345B47AA3674060B49412A51352BB183B55ABDBCAC92BC';

// Acme API key for /v1/login/verify (from clients.json)
const ACME_API_KEY = 'acme-test-key-2026';

// State
let currentNonce = null;
let currentMode = 'login'; // 'login' or 'enroll'
let relayWs = null;
let enrollmentInterval = null;

// DOM Elements
const loginView = document.getElementById('login-view');
const qrView = document.getElementById('qr-view');
const successView = document.getElementById('success-view');
const signedByBtn = document.getElementById('signedby-btn');
const backBtn = document.getElementById('back-btn');
const rewardAmount = document.getElementById('reward-amount');
const rewardInfo = document.getElementById('reward-info');
const statusText = document.getElementById('status-text');
const spinner = document.getElementById('spinner');
const qrTitle = document.getElementById('qr-title');
const qrSubtitle = document.getElementById('qr-subtitle');

// Enrollment section elements (auto-displayed on page load)
const enrollQrContainer = document.getElementById('enroll-qr-container');
const enrollStatus = document.getElementById('enroll-status');
const enrollTimer = document.getElementById('enroll-timer');

// Success view elements
const tokenSub = document.getElementById('token-sub');
const tokenIss = document.getElementById('token-iss');
const tokenAud = document.getElementById('token-aud');
const tokenMembership = document.getElementById('token-membership');
const tokenPayment = document.getElementById('token-payment');
const membershipField = document.getElementById('membership-field');
const payoutAmount = document.getElementById('payout-amount');
const payoutInfo = document.getElementById('payout-info');
const payoutError = document.getElementById('payout-error');
const payoutErrorMsg = document.getElementById('payout-error-msg');

// Event Listeners
if (signedByBtn) signedByBtn.addEventListener('click', startSignedByLogin);
if (backBtn) backBtn.addEventListener('click', cancelFlow);

// Auto-start enrollment QR on page load
document.addEventListener('DOMContentLoaded', initEnrollmentQR);

// ============================================================================
// NOSTR Cryptographic Functions (subset of nostr-tools for signing)
// ============================================================================

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA-256 hash using Web Crypto API
 */
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return new Uint8Array(hashBuffer);
}

/**
 * Compute NOSTR event ID (NIP-01)
 * ID = SHA256(JSON.stringify([0, pubkey, created_at, kind, tags, content]))
 */
async function computeEventId(event) {
    const serialized = JSON.stringify([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content
    ]);
    const hash = await sha256(serialized);
    return bytesToHex(hash);
}

/**
 * Sign a message with secp256k1 Schnorr signature (BIP-340)
 * Uses the Web Crypto subtle API with the noble-secp256k1 algorithm
 * 
 * For browser compatibility, we use the nostr-tools/pure approach
 */
async function schnorrSign(messageHash, privateKeyHex) {
    // We need secp256k1 Schnorr signing which isn't in Web Crypto
    // Import nostr-tools dynamically or use a minimal implementation
    
    // For now, use the nostr object if nostr-tools is loaded
    if (typeof nostrTools !== 'undefined' && nostrTools.finalizeEvent) {
        return null; // Will use finalizeEvent instead
    }
    
    // Fallback: we need nostr-tools for proper Schnorr signing
    throw new Error('nostr-tools library required for signing');
}

/**
 * Finalize and sign a NOSTR event
 * @param eventTemplate - Unsigned event object
 * @param privateKeyNsec - Private key in nsec (bech32) format
 */
async function signNostrEvent(eventTemplate, privateKeyNsec) {
    if (typeof window.nostrFinalizeEvent !== 'function') {
        throw new Error('nostr-tools not loaded');
    }
    if (!window.nip19?.decode) {
        throw new Error('nip19 decoder not loaded');
    }
    
    const decoded = window.nip19.decode(privateKeyNsec);
    if (decoded.type !== 'nsec') {
        throw new Error(`Expected nsec, got ${decoded.type}`);
    }
    
    return window.nostrFinalizeEvent(eventTemplate, decoded.data);
}

// ============================================================================
// Common Functions
// ============================================================================

/**
 * Generate a cryptographically secure nonce
 * 16 bytes, hex-encoded = 32 characters
 */
function generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Cancel current flow and go back
 */
function cancelFlow() {
    closeRelay();
    stopEnrollmentRefresh();
    currentNonce = null;
    currentMode = 'login';
    
    qrView.classList.add('hidden');
    successView.classList.add('hidden');
    loginView.classList.remove('hidden');
}

// ============================================================================
// ENROLLMENT FLOW (Phase 26.9) - Auto-displayed on page load
// ============================================================================

/**
 * Initialize enrollment QR on page load
 * Automatically generates nonce, publishes kind 28200, shows QR
 * Regenerates every 90 seconds
 */
async function initEnrollmentQR() {
    if (ACME_PRIVKEY_NSEC === '%%ACME_PRIVKEY_NSEC%%') {
        if (enrollStatus) enrollStatus.textContent = 'Enrollment not configured';
        console.warn('Enrollment not configured - Acme enterprise private key not set');
        return;
    }
    
    try {
        currentMode = 'enroll';
        
        // Generate and publish first enrollment event
        await generateEnrollmentQR();
        
        // Set up 90-second refresh
        enrollmentInterval = setInterval(async () => {
            console.log('Refreshing enrollment QR...');
            await generateEnrollmentQR();
        }, 90 * 1000);
        
        // Subscribe to relay for enrollment completion (kind 28201)
        subscribeToEnrollmentCompletion();
        
    } catch (error) {
        console.error('Error initializing enrollment:', error);
        if (enrollStatus) enrollStatus.textContent = 'Error: ' + error.message;
    }
}

/**
 * Generate enrollment QR code and publish kind 28200 event
 */
async function generateEnrollmentQR() {
    // Generate nonce locally - NO API call
    currentNonce = generateNonce();
    console.log('Generated enrollment nonce:', currentNonce);
    
    // Build kind 28200 event per Bible spec
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes
    const createdAt = Math.floor(Date.now() / 1000);
    
    const eventTemplate = {
        kind: 28200,
        created_at: createdAt,
        tags: [
            ['nonce', currentNonce],
            ['c', CLIENT_ID]
        ],
        content: JSON.stringify({
            client_id: CLIENT_ID,
            expires_at: expiresAt
        })
    };
    
    // Sign and finalize the event
    const signedEvent = await signNostrEvent(eventTemplate, ACME_PRIVKEY_NSEC);
    console.log('Signed enrollment event:', signedEvent);
    
    // Publish to relay
    await publishToRelay(signedEvent);
    
    // Generate QR code: signedby://enroll/{client_id}/{nonce}?exp={unix_timestamp_90s}
    const qrExpiry = Math.floor(Date.now() / 1000) + 90;
    const qrData = `signedby://enroll/${CLIENT_ID}/${currentNonce}?exp=${qrExpiry}`;
    console.log('Enrollment QR data:', qrData);
    
    // Render QR in the enrollment section (on login view)
    if (enrollQrContainer) {
        enrollQrContainer.innerHTML = '';
        new QRCode(enrollQrContainer, {
            text: qrData,
            width: 180,
            height: 180,
            colorDark: '#059669', // Green for enrollment
            colorLight: '#ffffff'
        });
    }
    
    // Update enrollment status
    if (enrollStatus) enrollStatus.textContent = 'Scan to become a member';
    
    // Start enrollment timer countdown
    startEnrollmentTimer(90);
}

/**
 * Publish event to NOSTR relay
 */
async function publishToRelay(event) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(RELAY_URL);
        
        ws.onopen = () => {
            console.log('Publishing event to relay...');
            const msg = JSON.stringify(['EVENT', event]);
            ws.send(msg);
        };
        
        ws.onmessage = (e) => {
            try {
                const response = JSON.parse(e.data);
                console.log('Relay response:', response);
                
                if (response[0] === 'OK') {
                    if (response[2] === true) {
                        console.log('Event published successfully:', response[1]);
                        ws.close();
                        resolve(response[1]);
                    } else {
                        ws.close();
                        reject(new Error(response[3] || 'Relay rejected event'));
                    }
                }
            } catch (err) {
                console.error('Error parsing relay response:', err);
            }
        };
        
        ws.onerror = (err) => {
            console.error('Relay connection error:', err);
            reject(new Error('Failed to connect to relay'));
        };
        
        // Timeout after 5 seconds
        setTimeout(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.close();
                reject(new Error('Relay publish timeout'));
            }
        }, 5000);
    });
}

/**
 * Subscribe to relay for enrollment completion events
 */
function subscribeToEnrollmentCompletion() {
    closeRelay();
    
    console.log('Connecting to relay for enrollment:', RELAY_URL);
    relayWs = new WebSocket(RELAY_URL);
    
    relayWs.onopen = () => {
        console.log('Relay connected, subscribing to enrollment events');
        const subRequest = JSON.stringify([
            "REQ",
            "enroll-sub",
            {
                kinds: [28200],
                authors: [ACME_PUBKEY_HEX]
            }
        ]);
        relayWs.send(subRequest);
    };
    
    relayWs.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            console.log('Relay message:', msg);
            
            if (msg[0] === 'EVENT' && msg[1] === 'enroll-sub') {
                const nostrEvent = msg[2];
                if (nostrEvent.kind === 28200) {
                    // Verify nonce tag matches current enrollment
                    const nonceTag = nostrEvent.tags.find(t => t[0] === 'nonce');
                    if (!nonceTag || nonceTag[1] !== currentNonce) return;
                    
                    handleEnrollmentEvent(nostrEvent);
                }
            } else if (msg[0] === 'EOSE') {
                console.log('End of stored events');
            }
        } catch (error) {
            console.error('Error parsing relay message:', error);
        }
    };
    
    relayWs.onerror = (error) => {
        console.error('Relay error:', error);
    };
    
    relayWs.onclose = () => {
        console.log('Relay connection closed');
    };
}

/**
 * Handle enrollment event from relay
 */
function handleEnrollmentEvent(event) {
    console.log('Enrollment event received:', event);
    // TODO: Handle enrollment completion
}

/**
 * Stop enrollment QR refresh
 */
function stopEnrollmentRefresh() {
    if (enrollmentInterval) {
        clearInterval(enrollmentInterval);
        enrollmentInterval = null;
    }
}

/**
 * Start enrollment countdown timer (displayed in login view)
 */
let enrollmentTimerInterval = null;
function startEnrollmentTimer(seconds) {
    if (enrollmentTimerInterval) {
        clearInterval(enrollmentTimerInterval);
    }
    
    let remaining = seconds;
    
    const updateTimer = () => {
        if (enrollTimer) enrollTimer.textContent = remaining;
        
        if (remaining <= 0) {
            // Timer hit zero - will be regenerated by enrollmentInterval
            if (enrollTimer) enrollTimer.textContent = '...';
        } else {
            remaining--;
        }
    };
    
    updateTimer();
    enrollmentTimerInterval = setInterval(updateTimer, 1000);
}

// ============================================================================
// LOGIN FLOW (existing)
// ============================================================================

/**
 * Start SignedByMe login flow
 */
async function startSignedByLogin() {
    try {
        currentMode = 'login';
        signedByBtn.disabled = true;
        signedByBtn.textContent = 'Starting...';
        
        // Generate nonce locally - no server call
        currentNonce = generateNonce();
        console.log('Generated nonce:', currentNonce);
        
        // Update UI
        if (qrTitle) qrTitle.textContent = 'Scan with SignedByMe';
        if (qrSubtitle) qrSubtitle.textContent = 'Open the SignedByMe app and scan this code';
        if (rewardInfo) rewardInfo.classList.remove('hidden');
        if (rewardAmount) rewardAmount.textContent = AMOUNT_SATS;
        
        // Generate QR code with deep link: signedby://{client_id}/{nonce}/{amount_sats}
        const qrData = `signedby://${CLIENT_ID}/${currentNonce}/${AMOUNT_SATS}`;
        console.log('QR data:', qrData);
        
        const qrContainer = document.getElementById('qr-container');
        qrContainer.innerHTML = ''; // Clear previous
        new QRCode(qrContainer, {
            text: qrData,
            width: 250,
            height: 250,
            colorDark: '#1a56db',
            colorLight: '#ffffff'
        });
        
        // Show QR view
        loginView.classList.add('hidden');
        qrView.classList.remove('hidden');
        
        // Subscribe to NOSTR relay for proof events
        subscribeToRelay(currentNonce);
        
        // Start 5-minute timer
        startExpiryTimer(300);
        
    } catch (error) {
        console.error('Error starting login:', error);
        alert('Failed to start login: ' + error.message);
    } finally {
        signedByBtn.disabled = false;
        signedByBtn.innerHTML = `
            <span class="icon">⚡</span>
            <div class="btn-text">
                Sign in with SignedByMe
                <span class="reward-badge">GET PAID TO LOG IN</span>
            </div>
        `;
    }
}

/**
 * Start expiry countdown timer
 */
function startExpiryTimer(seconds) {
    const expireTimer = document.getElementById('expire-timer');
    if (!expireTimer) return;
    
    let remaining = seconds;
    
    const updateTimer = () => {
        const mins = Math.floor(remaining / 60);
        const secs = remaining % 60;
        expireTimer.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
        
        if (remaining <= 0) {
            if (currentMode === 'login') {
                statusText.textContent = 'Session expired. Please try again.';
                spinner.style.display = 'none';
            }
            // For enrollment, the interval will regenerate
        } else {
            remaining--;
            setTimeout(updateTimer, 1000);
        }
    };
    
    updateTimer();
}

/**
 * Subscribe to NOSTR relay for proof events
 */
function subscribeToRelay(nonce) {
    closeRelay();
    
    console.log('Connecting to relay:', RELAY_URL);
    relayWs = new WebSocket(RELAY_URL);
    
    relayWs.onopen = () => {
        console.log('Relay connected, subscribing to nonce:', nonce);
        // Subscribe to kind 28101 events tagged with our nonce
        const subRequest = JSON.stringify([
            "REQ", 
            "login-sub", 
            { 
                kinds: [28101],
                "#nonce": [nonce]
            }
        ]);
        relayWs.send(subRequest);
        statusText.textContent = 'Waiting for scan...';
    };
    
    relayWs.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            console.log('Relay message:', msg);
            
            if (msg[0] === 'EVENT' && msg[1] === 'login-sub') {
                const nostrEvent = msg[2];
                if (nostrEvent.kind === 28101) {
                    handleProofEvent(nostrEvent);
                }
            } else if (msg[0] === 'EOSE') {
                console.log('End of stored events');
            }
        } catch (error) {
            console.error('Error parsing relay message:', error);
        }
    };
    
    relayWs.onerror = (error) => {
        console.error('Relay error:', error);
        statusText.textContent = 'Connection error. Retrying...';
        // Retry after 3 seconds
        setTimeout(() => {
            if (currentNonce && currentMode === 'login') {
                subscribeToRelay(currentNonce);
            }
        }, 3000);
    };
    
    relayWs.onclose = () => {
        console.log('Relay connection closed');
    };
}

/**
 * Close relay connection
 */
function closeRelay() {
    if (relayWs) {
        relayWs.close();
        relayWs = null;
    }
}

/**
 * Handle proof event from relay
 */
async function handleProofEvent(event) {
    console.log('Proof event received:', event);
    statusText.textContent = 'Proof received! Processing payment...';
    spinner.style.borderTopColor = '#059669';
    
    try {
        const content = JSON.parse(event.content);
        
        // Extract fields per Bible spec
        const npub = content.public_outputs?.npub || content.npub;
        const merkle_root = content.public_outputs?.merkle_root || content.merkle_root;
        const userInvoice = content.invoices?.user_invoice || content.user_invoice;
        const operatorInvoice = content.invoices?.operator_invoice || content.operator_invoice;
        const proof = content.proof;
        
        if (!userInvoice || !operatorInvoice) {
            throw new Error('Missing invoices in proof event');
        }
        
        if (!npub || !merkle_root) {
            throw new Error('Missing public_outputs in proof event');
        }
        
        // Pay both invoices via Strike
        statusText.textContent = 'Paying invoices...';
        
        const [userPreimage, operatorPreimage] = await Promise.all([
            payInvoiceViaStrike(userInvoice),
            payInvoiceViaStrike(operatorInvoice)
        ]);
        
        console.log('Payments complete:', { userPreimage, operatorPreimage });
        statusText.textContent = 'Verifying proof...';
        
        // Submit to /v1/login/verify per Bible spec (stateless, one call)
        const verifyResponse = await fetch(`${API_BASE}/v1/login/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': ACME_API_KEY
            },
            body: JSON.stringify({
                proof: proof,
                public_outputs: {
                    merkle_root: merkle_root,
                    npub: npub
                },
                user_invoice: userInvoice,
                operator_invoice: operatorInvoice,
                preimage_hex: userPreimage,
                operator_preimage_hex: operatorPreimage
            })
        });
        
        if (!verifyResponse.ok) {
            const error = await verifyResponse.json();
            throw new Error(error.detail || 'Verification failed');
        }
        
        const result = await verifyResponse.json();
        console.log('Verification result:', result);
        
        // Success! Close relay and show result
        closeRelay();
        showSuccess(result);
        
    } catch (error) {
        console.error('Error handling proof event:', error);
        statusText.textContent = 'Error: ' + error.message;
        spinner.style.display = 'none';
    }
}

/**
 * Pay a BOLT11 invoice via Strike API
 * Returns the payment preimage
 */
async function payInvoiceViaStrike(bolt11) {
    if (!STRIKE_API_KEY) {
        // For testing without Strike key - simulate payment
        console.warn('No Strike API key - simulating payment');
        return 'simulated_preimage_' + Date.now();
    }
    
    // Create payment quote
    const quoteResponse = await fetch('https://api.strike.me/v1/payment-quotes/lightning', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${STRIKE_API_KEY}`
        },
        body: JSON.stringify({
            lnInvoice: bolt11,
            sourceCurrency: 'BTC'
        })
    });
    
    if (!quoteResponse.ok) {
        const error = await quoteResponse.json();
        throw new Error(`Strike quote failed: ${error.message || quoteResponse.status}`);
    }
    
    const quote = await quoteResponse.json();
    console.log('Strike quote:', quote);
    
    // Execute payment
    const payResponse = await fetch(`https://api.strike.me/v1/payment-quotes/${quote.paymentQuoteId}/execute`, {
        method: 'PATCH',
        headers: {
            'Authorization': `Bearer ${STRIKE_API_KEY}`
        }
    });
    
    if (!payResponse.ok) {
        const error = await payResponse.json();
        throw new Error(`Strike payment failed: ${error.message || payResponse.status}`);
    }
    
    const payment = await payResponse.json();
    console.log('Strike payment response:', payment);
    
    // Extract preimage (hex) - check common field names
    const preimage = payment.preimage || payment.paymentPreimage || payment.result?.preimage;
    
    if (!preimage) {
        console.error('Strike response missing preimage:', payment);
        throw new Error('No preimage in Strike response - check API response structure');
    }
    
    return preimage;
}

/**
 * Show success view with id_token contents
 */
function showSuccess(result) {
    // Decode id_token (JWT) to show claims
    const idToken = result.id_token;
    let claims = {};
    
    try {
        const parts = idToken.split('.');
        if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1]));
            claims = payload;
            console.log('JWT claims:', claims);
        }
    } catch (e) {
        console.error('Error decoding JWT:', e);
    }
    
    // Display token claims
    if (tokenSub) tokenSub.textContent = claims.sub || 'Unknown';
    if (tokenIss) tokenIss.textContent = claims.iss || API_BASE;
    if (tokenAud) tokenAud.textContent = claims.aud || CLIENT_ID;
    
    // Membership claims
    if (claims.membership_root && membershipField) {
        tokenMembership.textContent = `Root: ${claims.membership_root.substring(0, 16)}...`;
        membershipField.classList.remove('hidden');
    } else if (membershipField) {
        membershipField.classList.add('hidden');
    }
    
    // Payment proof
    if (tokenPayment) {
        if (claims.payment_hash) {
            tokenPayment.textContent = claims.payment_hash.substring(0, 32) + '...';
        } else if (claims.preimage) {
            tokenPayment.textContent = claims.preimage.substring(0, 32) + '...';
        } else {
            tokenPayment.textContent = 'Verified ✓';
        }
    }
    
    // Handle payout display
    if (payoutAmount) payoutAmount.textContent = AMOUNT_SATS;
    if (payoutInfo) payoutInfo.classList.remove('hidden');
    if (payoutError) payoutError.classList.add('hidden');
    
    console.log('Login successful! id_token:', idToken);
    
    // Show success view
    qrView.classList.add('hidden');
    successView.classList.remove('hidden');
}

// Handle page visibility
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && currentNonce && !qrView.classList.contains('hidden')) {
        if (currentMode === 'login' && (!relayWs || relayWs.readyState !== WebSocket.OPEN)) {
            subscribeToRelay(currentNonce);
        }
    }
});
