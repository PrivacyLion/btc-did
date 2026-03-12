/**
 * Acme Corp SignedByMe Integration
 * 
 * Flow:
 * 1. Generate nonce locally (no server call)
 * 2. Display QR code with deep link: signedby://{client_id}/{nonce}/{amount_sats}
 * 3. Subscribe to NOSTR relay for kind 28101 proof events (#n tag)
 * 4. On proof event: pay invoices via Strike, submit to /v1/login/verify
 * 5. Display id_token on success
 */

// Configuration
const API_BASE = 'https://api.beta.privacy-lion.com';
const RELAY_URL = 'wss://relay.privacy-lion.com';
const CLIENT_ID = 'acme';
const AMOUNT_SATS = 100;

// Strike API - signedby-demo key
const STRIKE_API_KEY = '4F683B6BDAD5E8ED8A345B47AA3674060B49412A51352BB183B55ABDBCAC92BC';

// State
let currentNonce = null;
let relayWs = null;

// DOM Elements
const loginView = document.getElementById('login-view');
const qrView = document.getElementById('qr-view');
const successView = document.getElementById('success-view');
const signedByBtn = document.getElementById('signedby-btn');
const backBtn = document.getElementById('back-btn');
const rewardAmount = document.getElementById('reward-amount');
const statusText = document.getElementById('status-text');
const spinner = document.getElementById('spinner');

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
signedByBtn.addEventListener('click', startSignedByLogin);
backBtn.addEventListener('click', cancelLogin);

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
 * Start SignedByMe login flow
 */
async function startSignedByLogin() {
    try {
        signedByBtn.disabled = true;
        signedByBtn.textContent = 'Starting...';
        
        // Generate nonce locally - no server call
        currentNonce = generateNonce();
        console.log('Generated nonce:', currentNonce);
        
        // Update UI
        rewardAmount.textContent = AMOUNT_SATS;
        
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
 * Subscribe to NOSTR relay for proof events
 */
function subscribeToRelay(nonce) {
    closeRelay();
    
    console.log('Connecting to relay:', RELAY_URL);
    relayWs = new WebSocket(RELAY_URL);
    
    relayWs.onopen = () => {
        console.log('Relay connected, subscribing to nonce:', nonce);
        // Subscribe to kind 28101 events tagged with our nonce via #n tag
        const subRequest = JSON.stringify([
            "REQ", 
            "login-sub", 
            { 
                kinds: [28101],
                "#n": [nonce]
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
            if (currentNonce) {
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
        const npub = content.public_outputs.npub;
        const merkle_root = content.public_outputs.merkle_root;
        const userInvoice = content.invoices.user_invoice;
        const operatorInvoice = content.invoices.operator_invoice;
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
        
        // Submit to /v1/login/verify per Bible spec
        const verifyResponse = await fetch(`${API_BASE}/v1/login/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
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
    console.log('Strike payment:', payment);
    
    // Return preimage (hex)
    if (!payment.preimage) {
        throw new Error('No preimage in Strike response');
    }
    
    return payment.preimage;
}

/**
 * Cancel login and go back
 */
function cancelLogin() {
    closeRelay();
    currentNonce = null;
    
    qrView.classList.add('hidden');
    loginView.classList.remove('hidden');
}

/**
 * Show success view with id_token contents
 */
function showSuccess(result) {
    // Decode id_token (JWT) to show claims
    const idToken = result.id_token;
    let claims = {};
    
    try {
        // Decode JWT payload (middle part)
        const parts = idToken.split('.');
        if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1]));
            claims = payload;
        }
    } catch (e) {
        console.error('Error decoding JWT:', e);
    }
    
    // Display token claims
    tokenSub.textContent = claims.sub || 'Unknown';
    tokenIss.textContent = claims.iss || API_BASE;
    tokenAud.textContent = claims.aud || CLIENT_ID;
    
    // Membership claims (if present)
    if (claims.membership_root) {
        tokenMembership.textContent = `Root: ${claims.membership_root.substring(0, 16)}...`;
        membershipField.classList.remove('hidden');
    } else {
        membershipField.classList.add('hidden');
    }
    
    // Payment proof
    if (claims.payment_hash) {
        tokenPayment.textContent = claims.payment_hash.substring(0, 32) + '...';
    } else {
        tokenPayment.textContent = 'Verified ✓';
    }
    
    // Handle payout display
    payoutAmount.textContent = AMOUNT_SATS;
    payoutInfo.classList.remove('hidden');
    payoutError.classList.add('hidden');
    
    // Show success view
    qrView.classList.add('hidden');
    successView.classList.remove('hidden');
}

// Handle page visibility (pause/resume relay)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Could pause relay here if needed
    } else if (currentNonce && !qrView.classList.contains('hidden')) {
        // Reconnect if disconnected
        if (!relayWs || relayWs.readyState !== WebSocket.OPEN) {
            subscribeToRelay(currentNonce);
        }
    }
});
