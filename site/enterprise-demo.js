/**
 * SignedByMe Enterprise Demo
 * 
 * Bible-compliant stateless authentication:
 * 1. Enterprise generates nonce locally
 * 2. Displays QR: signedby://{client_id}/{nonce}/{amount_sats}
 * 3. Subscribes to NOSTR relay for proof_event tagged with nonce
 * 4. When proof arrives: pays both invoices, calls POST /v1/login/verify
 * 5. Displays id_token
 * 
 * NO SERVER CALLS FOR QR GENERATION (Decision 10)
 */
(function() {
  const API = "https://api.signedbyme.com";
  const CLIENT_ID = "acme";  // Enterprise client ID
  
  // SignedByMe relay infrastructure (Phase 29: Multi-relay)
  const SIGNEDBY_RELAYS = [
    'wss://relay.signedbyme.com',      // US East (ATL) - primary
    'wss://relay-sfo.signedbyme.com',  // US West (SFO)
    'wss://relay-ams.signedbyme.com',  // Europe (AMS)
    'wss://relay-sgp.signedbyme.com',  // Asia (SGP)
  ];
  // Legacy single URL for backwards compatibility
  const NOSTR_RELAY = SIGNEDBY_RELAYS[0];
  
  let state = {
    nonce: null,
    amountSats: 100,
    strikeApiKey: null,
    ws: null,
    proofEvent: null,
    userInvoice: null,
    operatorInvoice: null,
    userPreimage: null,
    operatorPreimage: null,
    idToken: null
  };

  // DOM helpers
  const $ = (sel) => document.querySelector(sel);
  const show = (id) => document.getElementById(id)?.classList.remove('hidden');
  const hide = (id) => document.getElementById(id)?.classList.add('hidden');
  
  function setStep(n) {
    for (let i = 1; i <= 4; i++) {
      const el = $(`#step${i}`);
      el?.classList.remove('active', 'done');
      if (i < n) el?.classList.add('done');
      if (i === n) el?.classList.add('active');
    }
  }

  function setStatus(id, msg, type = '') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
    el.className = 'status ' + type;
    show(id);
  }

  // Generate random nonce locally (16 bytes hex = 32 chars)
  function generateNonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Build QR data in Bible format
  function buildQrData(clientId, nonce, amountSats) {
    // Bible format: signedby://{client_id}/{nonce}/{amount_sats}
    return `signedby://${clientId}/${nonce}/${amountSats}`;
  }

  // Create session (local only - no server call!)
  function createSession() {
    const amount = parseInt($('#amount-sats')?.value) || 100;
    const strikeKey = $('#strike-api-key')?.value?.trim();
    
    // Generate nonce LOCALLY (Bible Decision 10)
    state.nonce = generateNonce();
    state.amountSats = amount;
    state.strikeApiKey = strikeKey || null;

    const qrData = buildQrData(CLIENT_ID, state.nonce, state.amountSats);
    
    setStatus('status-create', 
      `✓ Session created locally!\n\nClient ID: ${CLIENT_ID}\nNonce: ${state.nonce}\nAmount: ${amount} sats\n\nNo server call made (Bible Decision 10)`, 
      'success');

    // Show QR card
    setTimeout(() => showQR(qrData), 500);
    setStep(2);
  }

  function showQR(qrData) {
    hide('card-create');
    show('card-qr');

    // Generate QR code
    const container = $('#qr-container');
    if (container) {
      container.innerHTML = '';
      new QRCode(container, {
        text: qrData,
        width: 220,
        height: 220,
        colorDark: '#3B82F6',
        colorLight: '#ffffff'
      });
    }

    // Show deep link
    const deepLinkEl = $('#deep-link');
    if (deepLinkEl) deepLinkEl.textContent = qrData;

    // Connect to NOSTR relay and subscribe
    connectNostr();

    let statusMsg = `Nonce: ${state.nonce}\n\nWaiting for user to scan QR...\n`;
    statusMsg += `Listening on: ${NOSTR_RELAY}\n\n`;
    if (state.strikeApiKey) {
      statusMsg += '✓ Strike API configured — real payments enabled!';
    } else {
      statusMsg += 'ℹ No Strike API key — manual payment confirmation required';
    }
    setStatus('status-waiting', statusMsg, 'pending');
  }

  // Connect to NOSTR relay and subscribe for proof_event
  function connectNostr() {
    if (state.ws) {
      state.ws.close();
    }

    setStatus('status-waiting', `Connecting to NOSTR relay: ${NOSTR_RELAY}...`, 'pending');
    
    try {
      state.ws = new WebSocket(NOSTR_RELAY);
      
      state.ws.onopen = () => {
        console.log('NOSTR relay connected');
        
        // Subscribe for proof_event (kind 28101) tagged with our nonce
        // Filter: kind=28101, #n=<nonce>
        const subId = 'proof_' + state.nonce.slice(0, 8);
        const filter = {
          kinds: [28101],
          '#n': [state.nonce],
          limit: 1
        };
        
        const req = JSON.stringify(['REQ', subId, filter]);
        state.ws.send(req);
        
        setStatus('status-waiting', 
          `Connected to NOSTR relay!\n\nSubscription: ${subId}\nFilter: kind=28101, nonce=${state.nonce}\n\nWaiting for proof_event from mobile app...`,
          'pending');
      };
      
      state.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          console.log('NOSTR message:', msg);
          
          if (msg[0] === 'EVENT') {
            const nostrEvent = msg[2];
            if (nostrEvent.kind === 28101) {
              handleProofEvent(nostrEvent);
            }
          }
        } catch (e) {
          console.error('NOSTR parse error:', e);
        }
      };
      
      state.ws.onerror = (err) => {
        console.error('NOSTR error:', err);
        setStatus('status-waiting', `NOSTR error: ${err.message || 'Connection failed'}`, 'error');
      };
      
      state.ws.onclose = () => {
        console.log('NOSTR relay disconnected');
      };
      
    } catch (e) {
      console.error('NOSTR connection error:', e);
      setStatus('status-waiting', `Failed to connect: ${e.message}`, 'error');
    }
  }

  // Handle proof_event from mobile app
  function handleProofEvent(event) {
    console.log('Received proof_event:', event);
    state.proofEvent = event;
    
    // Parse content (JSON with proof, invoices)
    try {
      const content = JSON.parse(event.content);
      state.userInvoice = content.user_invoice;
      state.operatorInvoice = content.operator_invoice;
      
      setStatus('status-waiting', 
        `✓ Proof received from mobile app!\n\nUser invoice: ${state.userInvoice?.slice(0, 40)}...\nOperator invoice: ${state.operatorInvoice?.slice(0, 40)}...\n\nProceeding to payment...`,
        'success');
      
      // Show invoice card
      setTimeout(() => showInvoiceCard(), 500);
      
    } catch (e) {
      console.error('Failed to parse proof_event content:', e);
      setStatus('status-waiting', `Error parsing proof: ${e.message}`, 'error');
    }
  }

  function showInvoiceCard() {
    hide('card-qr');
    show('card-invoice');
    setStep(3);

    const invoiceDisplay = $('#invoice-display');
    if (invoiceDisplay) {
      invoiceDisplay.textContent = `User (90%): ${state.userInvoice?.slice(0, 60)}...\n\nOperator (10%): ${state.operatorInvoice?.slice(0, 60)}...`;
    }

    // Show Strike section if API key is configured
    if (state.strikeApiKey) {
      show('strike-pay-section');
    } else {
      hide('strike-pay-section');
    }
  }

  // Strike API payment
  async function strikePayInvoice(invoice) {
    if (!state.strikeApiKey) throw new Error('Strike API key not configured');
    
    const quoteResp = await fetch('https://api.strike.me/v1/payment-quotes/lightning', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.strikeApiKey}`
      },
      body: JSON.stringify({
        lnInvoice: invoice,
        sourceCurrency: 'BTC'
      })
    });
    
    if (!quoteResp.ok) {
      const err = await quoteResp.json();
      throw new Error(err.data?.message || err.message || 'Strike quote failed');
    }
    
    const quote = await quoteResp.json();
    
    const payResp = await fetch(`https://api.strike.me/v1/payment-quotes/${quote.paymentQuoteId}/execute`, {
      method: 'PATCH',
      headers: { 'Authorization': `Bearer ${state.strikeApiKey}` }
    });
    
    if (!payResp.ok) {
      const err = await payResp.json();
      throw new Error(err.data?.message || err.message || 'Strike payment failed');
    }
    
    const payment = await payResp.json();
    
    if (payment.preimage) {
      return payment.preimage;
    }
    
    throw new Error('Payment sent but preimage not returned');
  }

  async function payWithStrike() {
    if (!state.strikeApiKey) {
      alert('Strike API key not configured');
      return;
    }

    const btn = $('#btn-strike-pay');
    if (btn) {
      btn.textContent = 'Paying...';
      btn.disabled = true;
    }

    try {
      setStatus('status-invoice', '⚡ Paying user invoice (90%)...', 'pending');
      state.userPreimage = await strikePayInvoice(state.userInvoice);
      
      setStatus('status-invoice', '⚡ Paying operator invoice (10%)...', 'pending');
      state.operatorPreimage = await strikePayInvoice(state.operatorInvoice);
      
      setStatus('status-invoice', 
        `✓ Both invoices paid!\n\nUser preimage: ${state.userPreimage}\nOperator preimage: ${state.operatorPreimage}\n\nCalling /v1/login/verify...`,
        'success');
      
      // Call verify endpoint
      await verifyLogin();

    } catch (e) {
      console.error(e);
      setStatus('status-invoice', '✗ Strike payment failed: ' + e.message, 'error');
    } finally {
      if (btn) {
        btn.textContent = '⚡ Pay with Strike';
        btn.disabled = false;
      }
    }
  }

  async function verifyLogin() {
    try {
      setStatus('status-invoice', 'Calling /v1/login/verify...', 'pending');
      
      // Parse proof from event content
      const content = JSON.parse(state.proofEvent.content);
      
      const resp = await fetch(`${API}/v1/login/verify`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': 'acme-test-key-2026'  // TODO: configure
        },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          nonce: state.nonce,
          proof: content.proof,
          public_inputs: content.public_inputs,
          user_preimage: state.userPreimage,
          operator_preimage: state.operatorPreimage
        })
      });
      
      const data = await resp.json();
      
      if (!resp.ok) {
        throw new Error(data.detail || data.error || 'Verification failed');
      }
      
      state.idToken = data.id_token;
      setStatus('status-invoice', '✓ Login verified!', 'success');
      setTimeout(() => showVerified(), 500);

    } catch (e) {
      console.error(e);
      setStatus('status-invoice', '✗ Verify error: ' + e.message, 'error');
    }
  }

  function showVerified() {
    hide('card-invoice');
    show('card-verified');
    setStep(4);

    const tokenEl = $('#id-token');
    if (tokenEl) tokenEl.value = state.idToken;
  }

  function decodeToken() {
    try {
      const parts = state.idToken.split('.');
      if (parts.length !== 3) throw new Error('Invalid JWT');
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      
      setStatus('status-verified', 
        `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}`, 
        'success');
    } catch (e) {
      setStatus('status-verified', '✗ Error decoding: ' + e.message, 'error');
    }
  }

  function copyDeepLink() {
    const el = $('#deep-link');
    if (el) {
      navigator.clipboard.writeText(el.textContent);
      const btn = $('#btn-copy-link');
      if (btn) {
        const original = btn.textContent;
        btn.textContent = '✓ Copied!';
        setTimeout(() => btn.textContent = original, 2000);
      }
    }
  }

  function newSession() {
    if (state.ws) {
      state.ws.close();
      state.ws = null;
    }
    
    state = { 
      nonce: null,
      amountSats: 100,
      strikeApiKey: state.strikeApiKey,
      ws: null,
      proofEvent: null,
      userInvoice: null,
      operatorInvoice: null,
      userPreimage: null,
      operatorPreimage: null,
      idToken: null
    };
    
    hide('card-qr');
    hide('card-invoice');
    hide('card-verified');
    show('card-create');
    hide('status-create');
    setStep(1);
  }

  // Health check
  async function checkHealth() {
    try {
      const resp = await fetch(`${API}/healthz`);
      const data = await resp.json();
      setStatus('api-status', '✓ API is healthy\n' + JSON.stringify(data, null, 2), 'success');
    } catch (e) {
      setStatus('api-status', '✗ Error: ' + e.message, 'error');
    }
  }

  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    $('#btn-create-session')?.addEventListener('click', createSession);
    $('#btn-copy-link')?.addEventListener('click', copyDeepLink);
    $('#btn-new-session')?.addEventListener('click', newSession);
    $('#btn-strike-pay')?.addEventListener('click', payWithStrike);
    $('#btn-decode-token')?.addEventListener('click', decodeToken);
    $('#btn-start-over')?.addEventListener('click', newSession);
    $('#btn-health')?.addEventListener('click', checkHealth);

    setStep(1);
    console.log('SignedByMe Enterprise Demo initialized (Bible-compliant)');
  });
})();
