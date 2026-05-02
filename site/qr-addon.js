/* Demo glue wired to this page's IDs:
   Buttons:  btn-demo-qr, btn-demo-real, btn-demo-status, btn-demo-preimg
   Outputs:  #qr (QR), #status-line-1/2 (text), #login-status-json (pre)
*/
(function () {
  const api = "https://api.signedbyme.com";
  const $ = (sel) => document.querySelector(sel);
  const byId = (id) => document.getElementById(id);

  let CURRENT = { login_id: null, nonce: null, payment_hash: null };

  function setOutput(obj) {
    const el = byId("login-status-json");
    if (!el) return;
    try { el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2); }
    catch { el.textContent = String(obj); }
  }
  function setStatusLines() {
    const ch = CURRENT.login_id || CURRENT.nonce || "";
    const ph = CURRENT.payment_hash || "";
    const a = byId("status-line-1"), b = byId("status-line-2");
    if (a) a.textContent = ch ? `Challenge: ${ch}` : "";
    if (b) b.textContent = ph ? `Payment hash: ${ph}` : "";
  }
  function drawQR(text) {
    const box = byId("qr");
    if (!box) return;
    box.innerHTML = "";
    if (!text) return;
    new QRCode(box, { text, width: 256, height: 256 });
  }

  async function post(path, body) {
    const r = await fetch(`${api}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json();
    if (!r.ok) throw j;
    return j;
  }
  async function get(path) {
    const r = await fetch(`${api}${path}`);
    const j = await r.json();
    if (!r.ok) throw j;
    return j;
  }

  async function startLoginShowQR() {
    try {
      const resp = await post("/v1/login/start", { domain: window.location.hostname });
      setOutput(resp);

      CURRENT.login_id     = resp.login_id     ?? CURRENT.login_id;
      CURRENT.nonce        = resp.nonce        ?? CURRENT.nonce;
      CURRENT.payment_hash = resp.payment_hash ?? CURRENT.payment_hash;

      setStatusLines();
      const qrText = resp.invoice || CURRENT.login_id || CURRENT.nonce || "";
      drawQR(qrText);
    } catch (e) { console.error(e); setOutput(e); }
  }

  async function pollStatus() {
    try {
      if (!CURRENT.login_id) throw "No login_id yet. Click Start EA Login first.";
      const s = await get(`/v1/login/status/${encodeURIComponent(CURRENT.login_id)}`);
      setOutput(s);
    } catch (e) { console.error(e); setOutput(e); }
  }

  async function verifyWithPreimage() {
    try {
      if (!CURRENT.login_id) throw "No login_id yet. Click Start EA Login first.";
      const pre = [...crypto.getRandomValues(new Uint8Array(32))]
        .map(b => b.toString(16).padStart(2,"0")).join("");
      const url = `/v1/login/settle?login_id=${encodeURIComponent(CURRENT.login_id)}&preimage=${pre}&txid=`;
      const s = await post(url, {}); // POST with query (API expects this)
      setOutput(s);
    } catch (e) { console.error(e); setOutput(e); }
  }

  async function completeLogin() {
    try {
      if (!CURRENT.login_id || !CURRENT.nonce) throw "Need login_id and nonce. Start EA Login first.";
      const body = {
        login_id: CURRENT.login_id,
        did_sig: { did: "did:pl:testuser", pubkey_hex: "deadbeef", message: CURRENT.nonce, signature_hex: "00" },
        zk_proof: null, dlc: null
      };
      const r = await post("/v1/login/complete", body);
      setOutput(r);
    } catch (e) { console.error(e); setOutput(e); }
  }

  // Bind to your current button IDs
  function bind(id, fn) { const el = byId(id); if (el) el.addEventListener("click", fn); }
  document.addEventListener("DOMContentLoaded", () => {
    bind("btn-demo-qr",     startLoginShowQR);
    bind("btn-demo-status", pollStatus);
    bind("btn-demo-preimg", verifyWithPreimage);
    bind("btn-demo-real",   completeLogin);
    console.log("qr-addon.js wired to btn-demo-* IDs");
  });

  // also expose globally in case inline handlers are added later
  window.startLoginShowQR = startLoginShowQR;
  window.pollStatus = pollStatus;
  window.verifyWithPreimage = verifyWithPreimage;
  window.completeLogin = completeLogin;
})();
