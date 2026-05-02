/**
 * SignedByMe Live NOSTR Event Feed
 * 
 * Displays real-time SignedByMe events from production relays.
 * Event kinds: 28101 (proof), 28102 (auth_complete), 28103 (login_complete),
 *              28200 (enrollment_auth), 28202 (enrollment_response),
 *              28250 (delegation), 28251 (revocation)
 */

// SignedByMe relay infrastructure
const RELAYS = [
    'wss://relay.signedbyme.com',
    'wss://relay-sfo.signedbyme.com',
    'wss://relay-ams.signedbyme.com',
    'wss://relay-sgp.signedbyme.com',
];

// SignedByMe event kinds
const EVENT_KINDS = [28101, 28102, 28103, 28200, 28202, 28250, 28251];

// Event type metadata
const EVENT_META = {
    28101: { name: 'Proof', class: 'proof', icon: '🔐' },
    28102: { name: 'Auth Complete', class: 'complete', icon: '✓' },
    28103: { name: 'Login Complete', class: 'complete', icon: '✓' },
    28200: { name: 'Authorization', class: 'auth', icon: '🏢' },
    28202: { name: 'Enrollment Response', class: 'auth', icon: '🤖' },
    28250: { name: 'Delegation', class: 'delegation', icon: '👤' },
    28251: { name: 'Revocation', class: 'revocation', icon: '🚫' },
};

// State
let ws = null;
let eventCount = 0;
let connected = false;
let exampleTimeout = null;

// DOM elements
let feedEl = null;

// Initialize on load
document.addEventListener('DOMContentLoaded', init);

function init() {
    feedEl = document.getElementById('event-feed');
    if (!feedEl) return;
    
    // Clear placeholder and show connecting message
    feedEl.innerHTML = '<div class="feed-status">Connecting to relay...</div>';
    
    // Connect to primary relay
    connectToRelay(RELAYS[0]);
    
    // Show examples after 5 seconds if no events
    exampleTimeout = setTimeout(showExampleEvents, 5000);
}

function connectToRelay(url) {
    if (ws) {
        ws.close();
    }
    
    ws = new WebSocket(url);
    
    ws.onopen = () => {
        connected = true;
        updateStatus(`Connected to ${url.replace('wss://', '')}`);
        
        // Subscribe to SignedByMe event kinds
        const subRequest = JSON.stringify([
            'REQ',
            'sbm-feed',
            { kinds: EVENT_KINDS }
        ]);
        ws.send(subRequest);
    };
    
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            
            if (msg[0] === 'EVENT' && msg[1] === 'sbm-feed') {
                // Clear example timeout on first real event
                if (exampleTimeout) {
                    clearTimeout(exampleTimeout);
                    exampleTimeout = null;
                }
                
                // Clear examples if showing
                if (eventCount === 0) {
                    clearFeed();
                }
                
                displayEvent(msg[2], false);
            }
        } catch (e) {
            console.error('Error parsing relay message:', e);
        }
    };
    
    ws.onerror = () => {
        updateStatus('Connection error — retrying...');
    };
    
    ws.onclose = () => {
        connected = false;
        // Reconnect after 3 seconds
        setTimeout(() => connectToRelay(url), 3000);
    };
}

function displayEvent(event, isExample = false) {
    const meta = EVENT_META[event.kind] || { name: 'Unknown', class: 'unknown', icon: '?' };
    const time = new Date(event.created_at * 1000).toLocaleTimeString();
    const npub = truncateNpub(event.pubkey);
    
    // Parse content for additional info
    let detail = '';
    try {
        const content = JSON.parse(event.content);
        if (content.client_id) detail = content.client_id;
        else if (content.scopes) detail = Object.keys(content.scopes).join(', ');
        else if (content.delegation_id) detail = 'revoked';
    } catch (e) {
        // Content not JSON, that's fine
    }
    
    // Check tags for client_id
    if (!detail && event.tags) {
        const cTag = event.tags.find(t => t[0] === 'c');
        if (cTag) detail = cTag[1];
    }
    
    const el = document.createElement('div');
    el.className = `feed-event ${meta.class}${isExample ? ' example' : ''}`;
    el.innerHTML = `
        <span class="event-time">${time}</span>
        <span class="event-kind">${meta.icon} ${event.kind}</span>
        <span class="event-name">${meta.name}</span>
        <span class="event-npub">${npub}</span>
        ${detail ? `<span class="event-detail">${detail}</span>` : ''}
        ${isExample ? '<span class="event-example-badge">example</span>' : ''}
    `;
    
    // Add to top of feed
    feedEl.insertBefore(el, feedEl.firstChild);
    
    // Keep max 20 events
    eventCount++;
    while (feedEl.children.length > 20) {
        feedEl.removeChild(feedEl.lastChild);
    }
}

function showExampleEvents() {
    if (eventCount > 0) return; // Real events came in
    
    clearFeed();
    updateStatus('Showing example events (waiting for live activity...)');
    
    // Example events demonstrating the flow
    const now = Math.floor(Date.now() / 1000);
    const examples = [
        { kind: 28200, pubkey: 'a1b2c3d4e5f6...', content: '{"client_id":"acme"}', created_at: now - 30, tags: [] },
        { kind: 28202, pubkey: 'f6e5d4c3b2a1...', content: '{"email":"user@example.com"}', created_at: now - 25, tags: [] },
        { kind: 28200, pubkey: 'a1b2c3d4e5f6...', content: '{"client_id":"acme","agent_npub":"npub1..."}', created_at: now - 20, tags: [] },
        { kind: 28250, pubkey: '1a2b3c4d5e6f...', content: '{"scopes":{"acme":["read","write"]}}', created_at: now - 15, tags: [] },
        { kind: 28101, pubkey: 'f6e5d4c3b2a1...', content: '{"merkle_root":"0x..."}', created_at: now - 10, tags: [['c', 'acme']] },
        { kind: 28103, pubkey: 'f6e5d4c3b2a1...', content: '{}', created_at: now - 5, tags: [['c', 'acme']] },
    ];
    
    // Display in reverse order (oldest first visually, but insertBefore flips it)
    examples.reverse().forEach(ex => displayEvent(ex, true));
}

function updateStatus(msg) {
    const statusEl = feedEl.querySelector('.feed-status');
    if (statusEl) {
        statusEl.textContent = msg;
    }
}

function clearFeed() {
    feedEl.innerHTML = '';
    eventCount = 0;
}

function truncateNpub(hex) {
    if (!hex || hex.length < 16) return hex || '?';
    return hex.substring(0, 8) + '...' + hex.substring(hex.length - 4);
}
