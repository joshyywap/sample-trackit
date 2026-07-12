// ===============================
// TrackIT - PURE FRONTEND (no API)
// Universal QR scanner:
// - Prefer BarcodeDetector (Chrome/Edge support)
// - Fallback to html5-qrcode
// - Fallback to Upload Image
// ===============================

// ---------- localStorage keys (frozen — tamper-proof) ----------
const LS = Object.freeze({
  session:   "trackit_session",
  users:     "trackit_users",
  items:     "trackit_items",
  borrows:   "trackit_borrows",
  lostFound: "trackit_lostfound",
  ratings:   "trackit_ratings"
});

// ---------- 5 fixed toolbox categories (frozen) ----------
const TOOLBOXES = Object.freeze([
  Object.freeze({ id: 1, name: "Toolbox 1",    icon: "" }),
  Object.freeze({ id: 2, name: "Toolbox 2",    icon: "" }),
  Object.freeze({ id: 3, name: "Toolbox 3",    icon: "" }),
  Object.freeze({ id: 4, name: "Toolbox 4",    icon: "" }),
  Object.freeze({ id: 5, name: "RANDOM ITEMs", icon: "" }),
]);

function toolboxName(id) {
  const t = TOOLBOXES.find(t => t.id === Number(id));
  return t ? t.name : "Unassigned";
}

// ============================================================
// SECURITY — Rate limiting (brute-force protection)
// ============================================================
const RL_MAX_ATTEMPTS  = 5;
const RL_LOCKOUT_MS    = 15 * 60 * 1000; // 15 minutes
const RL_KEY_PREFIX    = "trackit_rl_";

function getRateLimitKey(lrn) {
  // Only allow digit strings so we never build arbitrary LS keys
  return RL_KEY_PREFIX + String(lrn).replace(/[^0-9]/g, "");
}

function checkRateLimit(lrn) {
  const key  = getRateLimitKey(lrn);
  const data = readLS(key, { attempts: 0, lockedUntil: 0 });
  if (Date.now() < (data.lockedUntil || 0)) {
    const mins = Math.ceil((data.lockedUntil - Date.now()) / 60000);
    return { locked: true, mins };
  }
  return { locked: false };
}

function recordFailedAttempt(lrn) {
  const key  = getRateLimitKey(lrn);
  const data = readLS(key, { attempts: 0, lockedUntil: 0 });
  data.attempts = (data.attempts || 0) + 1;
  if (data.attempts >= RL_MAX_ATTEMPTS) {
    data.lockedUntil = Date.now() + RL_LOCKOUT_MS;
    data.attempts    = 0;
  }
  writeLS(key, data);
}

function clearRateLimit(lrn) {
  try { localStorage.removeItem(getRateLimitKey(lrn)); } catch {}
}

// ============================================================
// SECURITY — Input validators
// ============================================================
const VALID_ITEM_ID_RE   = /^ITEM-[0-9]{8}-[0-9]{6}-[0-9]{3}$/;
const VALID_BORROW_ID_RE = /^BORROW-[0-9]+$/;
const VALID_LF_ID_RE     = /^LF-[0-9]+$/;

function isValidItemIdFormat(id)   { return typeof id === "string" && VALID_ITEM_ID_RE.test(id); }
function isValidBorrowIdFormat(id) { return typeof id === "string" && VALID_BORROW_ID_RE.test(id); }

// Whitelist-only QR payload parser — accepts ONLY { id: string }
function safeParseQr(text) {
  try {
    if (typeof text !== "string" || text.length > 256) return null;
    const obj = JSON.parse(text);
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
    // Prototype-pollution guard
    if (Object.prototype.hasOwnProperty.call(obj, "__proto__")   ||
        Object.prototype.hasOwnProperty.call(obj, "constructor") ||
        Object.prototype.hasOwnProperty.call(obj, "prototype"))  return null;
    // Whitelist: only allow `id` key
    if (typeof obj.id !== "string" || !isValidItemIdFormat(obj.id)) return null;
    return { id: obj.id };
  } catch {
    return null;
  }
}

// ============================================================
// SECURITY — Safe localStorage helpers
// ============================================================
const ALLOWED_LS_KEYS = new Set(Object.values(LS));
// Also allow rate-limit keys dynamically via prefix check
function isAllowedKey(key) {
  return ALLOWED_LS_KEYS.has(key) || key.startsWith(RL_KEY_PREFIX);
}

function readLS(key, fallback) {
  if (!isAllowedKey(key)) return fallback;
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    if (raw.length > 5_000_000) return fallback; // 5 MB sanity cap
    const v = JSON.parse(raw);
    // Prototype-pollution guard on top-level value
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if (Object.prototype.hasOwnProperty.call(v, "__proto__")   ||
          Object.prototype.hasOwnProperty.call(v, "constructor") ||
          Object.prototype.hasOwnProperty.call(v, "prototype"))  return fallback;
    }
    if (v === null || v === undefined) return fallback;
    if (Array.isArray(fallback) && !Array.isArray(v)) return fallback;
    return v;
  } catch {
    return fallback;
  }
}

function writeLS(key, value) {
  if (!isAllowedKey(key)) return;
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage quota or security error — fail silently
  }
}

// ============================================================
// SECURITY — localStorage schema validators
// Reject tampered/malformed records before they touch the UI.
// ============================================================
function isValidUser(u) {
  return u && typeof u === "object" &&
    typeof u.fullName === "string" && isValidName(u.fullName) &&
    typeof u.lrn      === "string" && isValidLRN(u.lrn) &&
    typeof u.password === "string" && isValidPassword(u.password) &&
    typeof u.section  === "string";
}

function isValidItem(i) {
  return i && typeof i === "object" &&
    typeof i.id       === "string" && isValidItemIdFormat(i.id) &&
    typeof i.name     === "string" && i.name.length > 0 && i.name.length <= 60 &&
    typeof i.quantity === "number" && i.quantity >= 0 &&
    typeof i.toolbox  === "number" && [1,2,3,4,5].includes(i.toolbox) &&
    (i.description === undefined || i.description === null ||
      (typeof i.description === "string" && i.description.length <= 120));
}

function isValidBorrow(b) {
  return b && typeof b === "object" &&
    typeof b.borrowId === "string" && isValidBorrowIdFormat(b.borrowId) &&
    typeof b.itemId   === "string" && isValidItemIdFormat(b.itemId) &&
    typeof b.itemName === "string" &&
    typeof b.quantity === "number" && b.quantity > 0;
}

function isValidRating(r) {
  return r && typeof r === "object" &&
    typeof r.id        === "string" &&
    typeof r.stars     === "number" && r.stars >= 1 && r.stars <= 5 &&
    typeof r.text      === "string" && r.text.length <= 240 &&
    typeof r.dateAdded === "string";
}

function safeReadUsers()   { return readLS(LS.users,   []).filter(isValidUser); }
function safeReadItems()   { return readLS(LS.items,   []).filter(isValidItem); }
function safeReadBorrows() { return readLS(LS.borrows, []).filter(isValidBorrow); }
function safeReadLF()      { return readLS(LS.lostFound, []); }
function safeReadRatings() { return readLS(LS.ratings, []).filter(isValidRating); }

// ---------- helpers ----------
function nowISO() { return new Date().toISOString(); }

function escapeHtml(str) {
  return String(str)
    .replaceAll("&",  "&amp;")
    .replaceAll("<",  "&lt;")
    .replaceAll(">",  "&gt;")
    .replaceAll('"',  "&quot;")
    .replaceAll("'",  "&#039;");
}

function requireLogin() {
  const session = readLS(LS.session, { loggedIn: false });
  if (!session.loggedIn) { alert("Please login first."); return false; }
  return true;
}

function closeMenuPanel() {
  const menuToggle = document.getElementById("menuToggle");
  if (menuToggle) menuToggle.checked = true;
}

// ---------- generic modal open/close ----------
let savedScrollY = 0;

function showModal(overlayId) {
  const el = document.getElementById(overlayId);
  el.style.display = "flex";
  savedScrollY = window.scrollY || window.pageYOffset || 0;
  document.body.style.position = "fixed";
  document.body.style.top      = `-${savedScrollY}px`;
  document.body.style.left     = "0";
  document.body.style.right    = "0";
  document.body.style.width    = "100%";
  // Double rAF so the "is-showing" class is added on a later frame than
  // display:flex — otherwise the browser coalesces both changes and the
  // rise-in transition on .modal-box never plays.
  requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add("is-showing")));
}

function hideModal(overlayId) {
  const el = document.getElementById(overlayId);
  el.classList.remove("is-showing");
  setTimeout(() => {
    el.style.display = "none";
    document.body.style.position = "";
    document.body.style.top      = "";
    document.body.style.left     = "";
    document.body.style.right    = "";
    document.body.style.width    = "";
    window.scrollTo(0, savedScrollY);
  }, 260);
}
let audioCtx = null;

function playBeep() {
    try {
        if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }

        if (audioCtx.state === "suspended") {
            audioCtx.resume();
        }

        const now = audioCtx.currentTime;

        // Main beep
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();

        osc.type = "square";       // More like a barcode scanner
        osc.frequency.setValueAtTime(2200, now);

        gain.gain.setValueAtTime(0.25, now);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.06);

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        osc.start(now);
        osc.stop(now + 0.06);

        // Optional second beep (cashier style)
        setTimeout(() => {
            const osc2 = audioCtx.createOscillator();
            const gain2 = audioCtx.createGain();

            osc2.type = "square";
            osc2.frequency.setValueAtTime(1800, audioCtx.currentTime);

            gain2.gain.setValueAtTime(0.18, audioCtx.currentTime);
            gain2.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.04);

            osc2.connect(gain2);
            gain2.connect(audioCtx.destination);

            osc2.start();
            osc2.stop(audioCtx.currentTime + 0.04);
        }, 70);

    } catch (e) {
        console.error(e);
    }
}

// ===================================================
// AUTH FORM STATE
// ===================================================
let authMode = "login";

const fullNameInput  = document.getElementById("fullName");
const lrnInput       = document.getElementById("lrn");
const passwordInput  = document.getElementById("password");
const sectionInput   = document.getElementById("section");
const sectionRow     = document.getElementById("sectionRow");
const authError      = document.getElementById("authError");
const formHeading    = document.getElementById("formHeading");
const signupPrompt   = document.getElementById("signupPrompt");
const toggleModeLink = document.getElementById("toggleModeLink");

function sanitizeName(raw)    { return raw.replace(/[^A-Za-z ]/g, "").slice(0, 50).trim(); }
function sanitizeLRN(raw)     { return raw.replace(/[^0-9]/g, "").slice(0, 12); }
function sanitizeSection(raw) { return raw.replace(/[^A-Za-z0-9\- ]/g, "").slice(0, 20).trim(); }
function sanitizeText(raw, max) { return String(raw).replace(/[<>"'`;]/g, "").slice(0, max).trim(); }

function isValidName(v)     { return /^[A-Za-z ]{2,50}$/.test(v); }
function isValidLRN(v)      { return /^[0-9]{12}$/.test(v); }
function isValidPassword(v) { return typeof v === "string" && v.length >= 8 && v.length <= 64; }
function isValidSection(v)  { return /^[A-Za-z0-9\- ]{2,20}$/.test(v); }

toggleModeLink?.addEventListener("click", function(e) {
  e.preventDefault();
  authMode = authMode === "login" ? "register" : "login";
  updateFormLabels();
});

document.getElementById("backToChoiceLink")?.addEventListener("click", function(e) {
  e.preventDefault();
  showAuthChoice();
});

function updateFormLabels() {
  if (authMode === "login") {
    formHeading.textContent  = "Login";
    signupPrompt.textContent = "Don't have any account?";
    toggleModeLink.textContent = "Sign up";
    sectionRow.style.display = "none";
  } else {
    formHeading.textContent  = "Register";
    signupPrompt.textContent = "Already have an account?";
    toggleModeLink.textContent = "Login";
    sectionRow.style.display = "flex";
  }
  authError.textContent = "";
}

function showAuthForm(mode) {
  authMode = mode;
  document.getElementById("authChoice").style.display      = "none";
  document.getElementById("authFormWrapper").style.display = "block";
  updateFormLabels();
}

function showAuthChoice() {
  document.getElementById("authChoice").style.display      = "block";
  document.getElementById("authFormWrapper").style.display = "none";
  authError.textContent = "";
}

function togglePasswordVisibility() {
  const f    = document.getElementById("password");
  const icon = document.getElementById("togglePasswordIcon");
  if (!f) return;
  f.type = f.type === "password" ? "text" : "password";
  if (icon) icon.style.opacity = f.type === "text" ? "1" : "0.6";
}

// ===================================================
// REGISTER / LOGIN — with rate limiting + schema checks
// ===================================================
async function handleAuthSubmit(e) {
  e.preventDefault();
  authError.textContent = "";

  const rawName = fullNameInput.value.trim();
  const rawLRN  = lrnInput.value.trim();
  const password = passwordInput.value;

  const cleanName = sanitizeName(rawName);
  const cleanLRN  = sanitizeLRN(rawLRN);

  if (cleanName !== rawName || !isValidName(cleanName)) {
    authError.textContent = "Name must contain letters and spaces only (2–50).";
    return;
  }
  if (cleanLRN !== rawLRN || !isValidLRN(cleanLRN)) {
    authError.textContent = "LRN must be exactly 12 digits.";
    return;
  }
  if (!isValidPassword(password)) {
    authError.textContent = "Password must be 8–64 characters.";
    return;
  }

  // Rate-limit check (applies to both login & register attempts)
  const rl = checkRateLimit(cleanLRN);
  if (rl.locked) {
    authError.textContent = `Too many attempts. Try again in ${rl.mins} minute(s).`;
    return;
  }

  const users = safeReadUsers();

  if (authMode === "register") {
    const sectionClean = sanitizeSection(sectionInput.value.trim());
    if (!isValidSection(sectionClean)) {
      authError.textContent = "Section must be 2–20 chars (letters/numbers/-/space).";
      return;
    }
    if (users.some(u => u.lrn === cleanLRN)) {
      authError.textContent = "LRN already registered. Please login.";
      return;
    }
    users.push({ fullName: cleanName, lrn: cleanLRN, password, section: sectionClean });
    writeLS(LS.users, users);
    writeLS(LS.session, { loggedIn: true, fullName: cleanName, lrn: cleanLRN });
    clearRateLimit(cleanLRN);
    updateMenuUI();
  } else {
    const user = users.find(u => u.lrn === cleanLRN);
    if (!user || user.password !== password) {
      recordFailedAttempt(cleanLRN);
      // Generic message — don't reveal which field is wrong
      authError.textContent = "Invalid credentials.";
      return;
    }
    clearRateLimit(cleanLRN);
    writeLS(LS.session, { loggedIn: true, fullName: user.fullName, lrn: user.lrn });
    updateMenuUI();
  }

  fullNameInput.value = "";
  lrnInput.value      = "";
  passwordInput.value = "";
  if (sectionInput) sectionInput.value = "";
}

// ===================================================
// LOGOUT
// ===================================================
async function logout() {
  if (!confirm("Are you sure you want to logout?")) return;
  writeLS(LS.session, { loggedIn: false });
  updateMenuUI();
  closeMenuPanel();
}

// ===================================================
// MENU UI
// ===================================================
function updateMenuUI() {
  const session  = readLS(LS.session, { loggedIn: false });
  const loggedIn = !!session.loggedIn;
  const fullName = typeof session.fullName === "string" ? session.fullName : "Guest";
  const lrn      = typeof session.lrn      === "string" ? session.lrn      : "";

  document.getElementById("usrName").textContent = fullName;
  document.getElementById("usrLrn").textContent  = lrn;

  document.getElementById("authButtons").style.display    = loggedIn ? "none"  : "block";
  document.getElementById("accountButtons").style.display = loggedIn ? "block" : "none";

  const bottone1 = document.getElementById("bottone1");
  const bottone2 = document.getElementById("bottone2");
  if (bottone1) bottone1.style.display = loggedIn ? "" : "none";
  if (bottone2) bottone2.style.display = loggedIn ? "" : "none";

  // "Borrow Now" is the mirror image of the pair above: guests see it,
  // it disappears the moment someone logs in.
  const bottoneGuest = document.getElementById("bottoneGuest");
  if (bottoneGuest) bottoneGuest.style.display = loggedIn ? "none" : "";

  if (!loggedIn) showAuthChoice();
}

// ===================================================
// TOOLBOX GRID
// ===================================================
function updateToolboxCounts() {
  const items = safeReadItems();
  TOOLBOXES.forEach(t => {
    const count = items.filter(i => Number(i.toolbox) === t.id).length;
    const el    = document.getElementById(`toolboxCount${t.id}`);
    if (el) el.textContent = `${count} item${count === 1 ? "" : "s"}`;
  });
}

// ===================================================
// HOME SEARCH
// ===================================================
function renderHomeSearchResults() {
  const input     = document.getElementById("homeSearchInput");
  const container = document.getElementById("homeSearchResults");
  const term      = input.value.trim().toLowerCase().slice(0, 100);

  if (!term) { container.innerHTML = ""; return; }

  const items = safeReadItems()
    .filter(i => i.name.toLowerCase().includes(term))
    .sort((a, b) => a.name.localeCompare(b.name))
    .slice(0, 8);

  if (!items.length) {
    container.innerHTML = `<p class="emptyMsg">No matching items.</p>`;
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="itemRow homeSearchRow" data-toolbox="${item.toolbox}">
      ${item.imageDataUrl ? `<img src="${item.imageDataUrl}" class="itemThumb">` : `<div class="itemThumb"></div>`}
      <div class="itemInfo">
        <p class="name">${escapeHtml(item.name)}</p>
        <p class="meta">${escapeHtml(toolboxName(item.toolbox))} • Qty: ${item.quantity}</p>
      </div>
    </div>
  `).join("");

  // Attach click via event delegation — avoids inline onclick with untrusted data
  container.querySelectorAll(".homeSearchRow").forEach(row => {
    row.addEventListener("click", () => openToolboxView(Number(row.dataset.toolbox)));
  });
}

// ===================================================
// TOOLBOX VIEW MODAL
// ===================================================
let currentToolboxViewId = null;

function openToolboxView(id) {
  currentToolboxViewId = id;
  document.getElementById("toolboxViewTitle").textContent = toolboxName(id);
  document.getElementById("toolboxSearchInput").value     = "";
  document.getElementById("homeSearchInput").value        = "";
  document.getElementById("homeSearchResults").innerHTML  = "";
  renderToolboxItems();
  showModal("toolboxViewModalOverlay");
}

function closeToolboxView() {
  hideModal("toolboxViewModalOverlay");
  currentToolboxViewId = null;
}

function renderToolboxItems() {
  const container = document.getElementById("toolboxItemList");
  const search    = document.getElementById("toolboxSearchInput").value.trim().toLowerCase().slice(0, 100);

  const items = safeReadItems()
    .filter(i => Number(i.toolbox) === currentToolboxViewId)
    .filter(i => i.name.toLowerCase().includes(search))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (!items.length) {
    container.innerHTML = `<p class="emptyMsg">No items found.</p>`;
    return;
  }

  container.innerHTML = items.map(item => {
    const img = item.imageDataUrl
      ? `<img src="${item.imageDataUrl}" class="itemThumb">`
      : `<div class="itemThumb"></div>`;
    return `
      <div class="itemRow">
        ${img}
        <div class="itemInfo">
          <p class="name">${escapeHtml(item.name)}</p>
          <p class="meta">ID: ${escapeHtml(item.id)}</p>
        </div>
        <div class="itemQty">${item.quantity}</div>
      </div>
    `;
  }).join("");
}

// ===================================================
// ADD ITEM MODAL
// ===================================================
let currentItemId       = null;
let addItemImageDataUrl = null;
let selectedToolboxId   = null;

function renderToolboxChooser() {
  const wrap = document.getElementById("toolboxChooser");
  wrap.innerHTML = TOOLBOXES.map(t => `
    <div class="toolboxChip${selectedToolboxId === t.id ? " selected" : ""}" data-id="${t.id}">
      ${escapeHtml(t.name)}
    </div>
  `).join("");
  wrap.querySelectorAll(".toolboxChip").forEach(chip => {
    chip.addEventListener("click", () => selectToolbox(Number(chip.dataset.id)));
  });
}

function selectToolbox(id) {
  selectedToolboxId = id;
  renderToolboxChooser();
}

function openAddItemModal() {
  if (!requireLogin()) return;

  document.getElementById("itemName").value                  = "";
  document.getElementById("itemDescription").value           = "";
  document.getElementById("itemQuantity").value              = "";
  document.getElementById("itemImage").value                 = "";
  document.getElementById("itemImagePreview").style.display  = "none";
  document.getElementById("qrCodeContainer").innerHTML       = "";
  document.getElementById("saveQrBtn").style.display         = "none";
  document.getElementById("saveItemBtn").style.display       = "none";
  document.getElementById("itemFormError").textContent       = "";

  selectedToolboxId   = null;
  renderToolboxChooser();

  currentItemId = generateItemId();
  document.getElementById("generatedItemId").textContent = currentItemId;

  showModal("addItemModalOverlay");
  closeMenuPanel();
}

function closeAddItemModal() {
  hideModal("addItemModalOverlay");
  addItemImageDataUrl = null;
}

function generateItemId() {
  const now       = new Date();
  const datePart  = now.getFullYear().toString() +
                    String(now.getMonth() + 1).padStart(2, "0") +
                    String(now.getDate()).padStart(2, "0");
  const timePart  = String(now.getHours()).padStart(2, "0") +
                    String(now.getMinutes()).padStart(2, "0") +
                    String(now.getSeconds()).padStart(2, "0");
  const rand      = Math.floor(100 + Math.random() * 900);
  return `ITEM-${datePart}-${timePart}-${rand}`;
}

function previewItemImage(event) {
  const file = event.target.files[0];
  if (!file) return;
  // Only allow image/* types
  if (!file.type.startsWith("image/")) {
    alert("Please upload an image file.");
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    alert("Image must be under 5 MB.");
    return;
  }
  const reader = new FileReader();
  reader.onload = function(e) {
    addItemImageDataUrl = e.target.result;
    const preview   = document.getElementById("itemImagePreview");
    preview.src     = addItemImageDataUrl;
    preview.style.display = "block";
  };
  reader.readAsDataURL(file);
}

function generateItemQR() {
  const name      = sanitizeText(document.getElementById("itemName").value.trim(), 60);
  const quantity  = parseInt(document.getElementById("itemQuantity").value.trim(), 10);
  const errorEl   = document.getElementById("itemFormError");
  errorEl.textContent = "";

  if (!selectedToolboxId)          return (errorEl.textContent = "Please select a toolbox first.");
  if (!name)                       return (errorEl.textContent = "Please enter the item name first.");
  if (!quantity || quantity <= 0)  return (errorEl.textContent = "Please enter a valid quantity.");

  // QR encodes ONLY the id — name never goes into the QR payload
  const qrData     = JSON.stringify({ id: currentItemId });
  const qrContainer = document.getElementById("qrCodeContainer");
  qrContainer.innerHTML = "";
  new QRCode(qrContainer, { text: qrData, width: 150, height: 150 });

  document.getElementById("saveQrBtn").style.display  = "block";
  document.getElementById("saveItemBtn").style.display = "block";
}

async function saveItem() {
  const name        = sanitizeText(document.getElementById("itemName").value.trim(), 60);
  const description = sanitizeText(document.getElementById("itemDescription").value.trim(), 120);
  const quantity     = parseInt(document.getElementById("itemQuantity").value.trim(), 10);
  const errorEl      = document.getElementById("itemFormError");
  errorEl.textContent = "";

  if (!selectedToolboxId)         return (errorEl.textContent = "Please select a toolbox.");
  if (!name)                      return (errorEl.textContent = "Item name is required.");
  if (!quantity || quantity <= 0) return (errorEl.textContent = "Quantity must be at least 1.");

  const items = safeReadItems();
  items.push({
    id:           currentItemId,
    name,
    description,
    quantity,
    toolbox:      selectedToolboxId,
    imageDataUrl: addItemImageDataUrl || null,
    dateAdded:    nowISO()
  });
  writeLS(LS.items, items);

  updateToolboxCounts();
  renderItemCarousel();
  closeAddItemModal();
}

// ===================================================
// QR LABEL DOWNLOAD — ID only, QR maximized
// 3 cm × 4 cm at 300 DPI.
// No name. QR fills almost the full width. Only the
// item ID printed below in small monospace text.
// ===================================================
function wrapCanvasText(ctx, text, x, y, maxWidth, lineHeight) {
  const words = text.split(" ");
  let line = "", lines = [];
  for (const word of words) {
    const test = line + word + " ";
    if (ctx.measureText(test).width > maxWidth && line !== "") {
      lines.push(line.trim());
      line = word + " ";
    } else {
      line = test;
    }
  }
  lines.push(line.trim());
  lines.slice(0, 2).forEach((l, idx) => ctx.fillText(l, x, y + idx * lineHeight));
}

/**
 * Draws the QR label onto a canvas and triggers a download.
 * ID only — no name. QR is maximized to fill the label.
 */
function renderQrLabelCanvas(container, itemId, callback) {
  const source = container.querySelector("canvas") || container.querySelector("img");
  if (!source) { alert("Generate the QR code first."); return; }

  const DPI       = 300;
  const CM_TO_PX  = DPI / 2.54;
  const labelW    = Math.round(3 * CM_TO_PX); // ~354 px
  const labelH    = Math.round(4 * CM_TO_PX); // ~472 px

  const canvas = document.createElement("canvas");
  canvas.width  = labelW;
  canvas.height = labelH;
  const ctx = canvas.getContext("2d");

  // White background
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, labelW, labelH);

  // Margins — tiny, to maximise QR size
  const margin  = 6;
  const idAreaH = 28; // reserved at the bottom for the ID text
  const qrSize  = labelW - margin * 2;
  const qrY     = margin;

  ctx.imageSmoothingEnabled = false;

  const finish = () => {
    // ID text — centred, monospace, small
    ctx.textAlign   = "center";
    ctx.fillStyle   = "#222222";
    ctx.font        = `bold 16px monospace`;
    ctx.fillText(itemId, labelW / 2, qrY + qrSize + idAreaH / 2 + 5);
    callback(canvas);
  };

  if (source.tagName === "CANVAS") {
    ctx.drawImage(source, margin, qrY, qrSize, qrSize);
    finish();
  } else {
    const img = new Image();
    img.onload = () => { ctx.drawImage(img, margin, qrY, qrSize, qrSize); finish(); };
    img.src    = source.src;
  }
}

function downloadQrLabel(containerId, itemId) {
  const container = document.getElementById(containerId);
  renderQrLabelCanvas(container, itemId, (canvas) => {
    const link      = document.createElement("a");
    link.download   = `${itemId}.png`;
    link.href       = canvas.toDataURL("image/png");
    link.click();
  });
}

/** Called by the "Save QR" button inside Add Item modal */
function saveGeneratedQr() {
  downloadQrLabel("qrCodeContainer", currentItemId);
}

/**
 * Called by the "Download QR" button in Inventory.
 * Generates the QR in memory (no modal) then downloads immediately.
 */
function downloadItemQr(itemId) {
  if (!isValidItemIdFormat(itemId)) return;

  const items = safeReadItems();
  const item  = items.find(i => i.id === itemId);
  if (!item) return;

  // Off-screen temp container
  const tempDiv = document.createElement("div");
  tempDiv.style.cssText = "position:absolute;left:-9999px;top:-9999px;pointer-events:none;";
  document.body.appendChild(tempDiv);

  new QRCode(tempDiv, {
    // QR payload: ID only
    text:   JSON.stringify({ id: item.id }),
    width:  200,
    height: 200
  });

  // Small delay for QRCode lib to render the canvas
  setTimeout(() => {
    renderQrLabelCanvas(tempDiv, item.id, (canvas) => {
      const link    = document.createElement("a");
      link.download = `${item.id}.png`;
      link.href     = canvas.toDataURL("image/png");
      link.click();
      document.body.removeChild(tempDiv);
    });
  }, 120);
}

// ===================================================
// DELETE ITEM MODAL
// ===================================================
function openDeleteItemModal() {
  if (!requireLogin()) return;
  document.getElementById("deleteSearchInput").value    = "";
  document.getElementById("deleteItemError").textContent = "";
  renderDeleteItemList();
  showModal("deleteItemModalOverlay");
  closeMenuPanel();
}

function closeDeleteItemModal() { hideModal("deleteItemModalOverlay"); }

function renderDeleteItemList() {
  const container = document.getElementById("deleteItemList");
  const search    = document.getElementById("deleteSearchInput").value.trim().toLowerCase().slice(0, 100);

  const items = safeReadItems()
    .filter(i => i.name.toLowerCase().includes(search))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (!items.length) {
    container.innerHTML = `<p class="emptyMsg">No items in inventory.</p>`;
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="itemRow">
      ${item.imageDataUrl ? `<img src="${item.imageDataUrl}" class="itemThumb">` : `<div class="itemThumb"></div>`}
      <div class="itemInfo">
        <p class="name">${escapeHtml(item.name)}</p>
        <p class="meta">${escapeHtml(toolboxName(item.toolbox))} • Qty: ${item.quantity}</p>
      </div>
      <button class="deleteBtn" data-id="${escapeHtml(item.id)}">Delete</button>
    </div>
  `).join("");

  // Event delegation — avoids inline onclick with item IDs
  container.querySelectorAll(".deleteBtn").forEach(btn => {
    btn.addEventListener("click", () => confirmDeleteItem(btn.dataset.id));
  });
}

function confirmDeleteItem(id) {
  if (!isValidItemIdFormat(id)) return;
  const errorEl = document.getElementById("deleteItemError");
  errorEl.textContent = "";

  const borrows      = safeReadBorrows();
  const activeBorrow = borrows.find(b => b.itemId === id && !b.dateReturned);
  if (activeBorrow) {
    errorEl.textContent = "Cannot delete: this item is currently borrowed.";
    return;
  }
  if (!confirm("Delete this item permanently?")) return;

  writeLS(LS.items, safeReadItems().filter(i => i.id !== id));
  renderDeleteItemList();
  updateToolboxCounts();
  renderItemCarousel();
}

// ===================================================
// LOST AND FOUND MODAL
// ===================================================
let selectedLostStatus = "lost";

function selectLostStatus(status) {
  if (status !== "lost" && status !== "found") return; // whitelist
  selectedLostStatus = status;
  document.querySelectorAll("#lostStatusChooser .toolboxChip").forEach(chip => {
    chip.classList.toggle("selected", chip.dataset.status === status);
  });
}

function openLostFoundModal() {
  if (!requireLogin()) return;
  document.getElementById("lostItemName").value         = "";
  document.getElementById("lostDescription").value      = "";
  document.getElementById("lostFoundError").textContent = "";
  selectLostStatus("lost");
  renderLostFoundList();
  showModal("lostFoundModalOverlay");
  closeMenuPanel();
}

function closeLostFoundModal() { hideModal("lostFoundModalOverlay"); }

async function submitLostFound() {
  const errorEl     = document.getElementById("lostFoundError");
  errorEl.textContent = "";

  const name        = sanitizeText(document.getElementById("lostItemName").value.trim(), 60);
  const description = sanitizeText(document.getElementById("lostDescription").value.trim(), 100);

  if (!name || name.length > 60)        { errorEl.textContent = "Please enter a valid item name (max 60 characters)."; return; }
  if (description.length > 100)         { errorEl.textContent = "Description must be under 100 characters."; return; }
  if (selectedLostStatus !== "lost" && selectedLostStatus !== "found") return;

  const session = readLS(LS.session, { loggedIn: false });
  if (!session.loggedIn) return;

  const entries = safeReadLF();
  entries.push({
    id:            "LF-" + Date.now(),
    itemName:      name,
    description,
    status:        selectedLostStatus,
    reportedBy:    typeof session.fullName === "string" ? session.fullName : "Unknown",
    reportedByLrn: typeof session.lrn      === "string" ? session.lrn      : "",
    dateReported:  nowISO()
  });
  writeLS(LS.lostFound, entries);

  document.getElementById("lostItemName").value    = "";
  document.getElementById("lostDescription").value = "";
  renderLostFoundList();
}

function renderLostFoundList() {
  const container = document.getElementById("lostFoundList");
  const entries   = safeReadLF()
    .slice()
    .sort((a, b) => new Date(b.dateReported) - new Date(a.dateReported));

  if (!entries.length) {
    container.innerHTML = `<p class="emptyMsg">No lost or found items reported yet.</p>`;
    return;
  }

  container.innerHTML = entries.map(e => `
    <div class="itemRow">
      <div class="itemInfo">
        <p class="name">${escapeHtml(e.itemName)}</p>
        <p class="meta">${e.description ? escapeHtml(e.description) + " • " : ""}Reported by ${escapeHtml(e.reportedBy)} • ${new Date(e.dateReported).toLocaleDateString()}</p>
      </div>
      <span class="statusBadge ${e.status === "found" ? "returned" : "active"}">${e.status === "found" ? "Found" : "Lost"}</span>
    </div>
  `).join("");
}

// ===================================================
// BORROWER LIST MODAL
// ===================================================
function openBorrowerListModal() {
  if (!requireLogin()) return;
  document.getElementById("borrowerSearchInput").value = "";
  renderBorrowerList();
  showModal("borrowerListModalOverlay");
  closeMenuPanel();
}

function closeBorrowerListModal() { hideModal("borrowerListModalOverlay"); }

function renderBorrowerList() {
  const container = document.getElementById("borrowerListBox");
  const search    = document.getElementById("borrowerSearchInput").value.trim().toLowerCase().slice(0, 100);

  const borrows = safeReadBorrows()
    .filter(b =>
      b.borrowerName.toLowerCase().includes(search) ||
      b.itemName.toLowerCase().includes(search)
    )
    .sort((a, b) => new Date(b.dateBorrowed) - new Date(a.dateBorrowed));

  if (!borrows.length) {
    container.innerHTML = `<p class="emptyMsg">No borrow records yet.</p>`;
    return;
  }

  container.innerHTML = borrows.map(b => `
    <div class="itemRow">
      <div class="itemInfo">
        <p class="name">${escapeHtml(b.borrowerName)} <span style="color:#888; font-weight:400;">(${escapeHtml(b.borrowerSection)})</span></p>
        <p class="meta">${escapeHtml(b.itemName)} × ${b.quantity} • ${new Date(b.dateBorrowed).toLocaleDateString()}</p>
      </div>
      <div style="display:flex; flex-direction:column; align-items:flex-end; gap:6px;">
        <span class="statusBadge ${b.dateReturned ? "returned" : "active"}">${b.dateReturned ? "Returned" : "Active"}</span>
        <button class="seeInfoBtn" data-id="${escapeHtml(b.borrowId)}">See Info</button>
      </div>
    </div>
  `).join("");

  container.querySelectorAll(".seeInfoBtn").forEach(btn => {
    btn.addEventListener("click", () => openBorrowInfo(btn.dataset.id));
  });
}

// ===================================================
// BORROW RECORD INFO MODAL
// ===================================================
function openBorrowInfo(borrowId) {
  if (!isValidBorrowIdFormat(borrowId)) return;
  const borrows   = safeReadBorrows();
  const b         = borrows.find(x => x.borrowId === borrowId);
  const container = document.getElementById("borrowInfoContent");

  if (!b) {
    container.innerHTML = `<p class="emptyMsg">Record not found.</p>`;
    showModal("borrowInfoModalOverlay");
    return;
  }

  container.innerHTML = `
    <div class="infoSection">
      <p class="infoLabel">Borrower</p>
      <p class="infoValue">${escapeHtml(b.borrowerName)} • LRN: ${escapeHtml(b.borrowerLrn)}</p>
      <p class="infoValue">Section: ${escapeHtml(b.borrowerSection)}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Item</p>
      <p class="infoValue">${escapeHtml(b.itemName)} × ${b.quantity}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Provided By</p>
      <p class="infoValue">${escapeHtml(b.providerName || "Unknown")} • LRN: ${escapeHtml(b.providerLrn || "-")}</p>
      <p class="infoValue">Date borrowed: ${new Date(b.dateBorrowed).toLocaleString()}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Return Status</p>
      ${b.dateReturned
        ? `<p class="infoValue">Received by: ${escapeHtml(b.receiverName || "Unknown")} • LRN: ${escapeHtml(b.receiverLrn || "-")}</p>
           <p class="infoValue">Date returned: ${new Date(b.dateReturned).toLocaleString()}</p>`
        : `<p class="infoValue" style="color:crimson;">Still active — not yet returned.</p>`
      }
    </div>
  `;
  showModal("borrowInfoModalOverlay");
}

function closeBorrowInfo() { hideModal("borrowInfoModalOverlay"); }

// ===================================================
// SEARCH ITEM BY QR
// ===================================================
let searchByQrScanStop = null;

function openSearchByQrModal() {
  if (!requireLogin()) return;
  document.getElementById("searchByQrError").textContent    = "";
  document.getElementById("searchByQrScanStep").style.display   = "block";
  document.getElementById("searchByQrResultStep").style.display = "none";
  showModal("searchByQrModalOverlay");
  closeMenuPanel();
  startSearchByQrScan();
}

async function startSearchByQrScan() {
  if (searchByQrScanStop) await searchByQrScanStop();
  const controller = await startUniversalQrScan(
    "searchByQrReader",
    async (decodedText) => { await handleSearchByQrResult(decodedText); },
    (msg) => { document.getElementById("searchByQrError").textContent = msg; }
  );
  searchByQrScanStop = controller.stop;
}

async function closeSearchByQrModal() {
  hideModal("searchByQrModalOverlay");
  if (searchByQrScanStop) { await searchByQrScanStop(); searchByQrScanStop = null; }
}

async function handleSearchByQrResult(qrText) {
  const errorEl  = document.getElementById("searchByQrError");
  const itemData = safeParseQr(qrText);
  if (!itemData) { errorEl.textContent = "Invalid or unrecognized QR code."; return; }

  const item = safeReadItems().find(i => i.id === itemData.id);
  if (!item)  { errorEl.textContent = "Item not found in inventory."; return; }

  renderSearchByQrResult(item);
}

function renderSearchByQrResult(item) {
  document.getElementById("searchByQrScanStep").style.display   = "none";
  document.getElementById("searchByQrResultStep").style.display = "block";

  const container = document.getElementById("searchByQrResultContent");
  const img = item.imageDataUrl
    ? `<img src="${item.imageDataUrl}" style="width:100%; height:160px; object-fit:contain; border-radius:12px; margin-bottom:14px;">`
    : "";

  container.innerHTML = `
    ${img}
    <div class="infoSection">
      <p class="infoLabel">Item</p>
      <p class="infoValue">${escapeHtml(item.name)}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Toolbox</p>
      <p class="infoValue">${escapeHtml(toolboxName(item.toolbox))}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Quantity in Stock</p>
      <p class="infoValue">${item.quantity}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Item ID</p>
      <p class="infoValue">${escapeHtml(item.id)}</p>
    </div>
  `;
}

async function restartSearchByQrScan() {
  document.getElementById("searchByQrError").textContent        = "";
  document.getElementById("searchByQrResultStep").style.display = "none";
  document.getElementById("searchByQrScanStep").style.display   = "block";
  await startSearchByQrScan();
}

// ===================================================
// INVENTORY MODAL — Download QR button (no modal)
// ===================================================
async function openInventoryModal() {
  if (!requireLogin()) return;
  showModal("inventoryModalOverlay");
  closeMenuPanel();
  await loadInventory();
}

function closeInventoryModal() { hideModal("inventoryModalOverlay"); }

async function loadInventory() {
  const container = document.getElementById("inventoryList");
  const items     = safeReadItems();

  if (!items.length) {
    container.innerHTML = `<p class="emptyMsg">No items in inventory.</p>`;
    return;
  }

  container.innerHTML = TOOLBOXES.map(t => {
    const boxItems = items
      .filter(i => Number(i.toolbox) === t.id)
      .sort((a, b) => a.name.localeCompare(b.name));

    const rows = boxItems.length
      ? boxItems.map(item => {
          const img = item.imageDataUrl
            ? `<img src="${item.imageDataUrl}" style="width:55px;height:55px;object-fit:contain;border-radius:8px;">`
            : `<div style="width:55px;height:55px;background:#e3e3e8;border-radius:8px;"></div>`;
          return `
            <div class="itemRow">
              ${img}
              <div class="itemInfo">
                <p class="name">${escapeHtml(item.name)}</p>
                <p class="meta">Added: ${new Date(item.dateAdded).toLocaleDateString()}</p>
              </div>
              <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                <div style="text-align:right;">
                  <p style="margin:0;font-weight:bold;font-size:1.1em;color:#1797b8;">${item.quantity}</p>
                  <p style="margin:0;font-size:.7em;color:#888;">in stock</p>
                </div>
                <button class="seeInfoBtn dlQrBtn" data-id="${escapeHtml(item.id)}">Download QR</button>
              </div>
            </div>
          `;
        }).join("")
      : `<p class="emptyMsg">No items in this toolbox.</p>`;

    return `
      <div class="inventorySection">
        <p class="inventorySectionTitle">${escapeHtml(t.name)}</p>
        ${rows}
      </div>
    `;
  }).join("");

  // Safe event delegation — no inline onclick with item IDs
  container.querySelectorAll(".dlQrBtn").forEach(btn => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      if (isValidItemIdFormat(id)) downloadItemQr(id);
    });
  });
}

// ===================================================
// UNIVERSAL QR SCANNER
// ===================================================
async function startUniversalQrScan(targetDivId, onResult, onError) {
  const container = document.getElementById(targetDivId);
  container.innerHTML = "";

  if (!window.isSecureContext) {
    onError("Camera requires HTTPS (or localhost). Use Upload QR image instead.");
    return { stop: async () => {} };
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    onError("Camera not supported in this browser. Use Upload QR image.");
    return { stop: async () => {} };
  }

  const video = document.createElement("video");
  video.setAttribute("playsinline", "true");
  video.style.width        = "100%";
  video.style.borderRadius = "10px";
  container.appendChild(video);

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false
    });
  } catch {
    onError("Camera permission denied or camera unavailable. Use Upload QR image.");
    return { stop: async () => {} };
  }

  video.srcObject = stream;
  await video.play();

  const canUseBarcodeDetector =
    "BarcodeDetector" in window &&
    (await BarcodeDetector.getSupportedFormats?.())?.includes?.("qr_code");

  let stopped = false;

  if (canUseBarcodeDetector) {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });

    const stop = async () => {
      stopped = true;
      try { stream.getTracks().forEach(t => t.stop()); } catch {}
      try { video.pause(); } catch {}
      try { video.srcObject = null; } catch {}
    };

    const scanLoop = async () => {
      if (stopped) return;
      try {
        const codes = await detector.detect(video);
        if (codes?.length) {
          const text = codes[0].rawValue;
          await stop();
          playBeep();
          onResult(text);
          return;
        }
      } catch {}
      requestAnimationFrame(scanLoop);
    };

    requestAnimationFrame(scanLoop);
    return { stop };
  }

  // Fallback: html5-qrcode
  try { stream.getTracks().forEach(t => t.stop()); } catch {}

  if (typeof Html5Qrcode === "undefined") {
    onError("QR scan library not loaded. Use Upload QR image instead.");
    return { stop: async () => {} };
  }

  const html5 = new Html5Qrcode(targetDivId);
  html5.start(
    { facingMode: "environment" },
    { fps: 10, qrbox: 220 },
    async (decodedText) => {
      try { await html5.stop(); } catch {}
      try { html5.clear(); } catch {}
      playBeep();
      onResult(decodedText);
    },
    () => {}
  ).catch(err => onError("Camera error: " + err));

  return {
    stop: async () => {
      try { await html5.stop(); } catch {}
      try { html5.clear(); } catch {}
    }
  };
}

async function scanQrFromImageFile(event, mode) {
  const file = event.target.files?.[0];
  if (!file) return;

  // Validate file type before even touching BarcodeDetector
  if (!file.type.startsWith("image/")) {
    alert("Please upload a valid image file.");
    event.target.value = "";
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    alert("Image is too large (max 10 MB).");
    event.target.value = "";
    return;
  }

  if (!("BarcodeDetector" in window)) {
    alert("Upload QR scanning not supported in this browser. Try Chrome/Edge, or use camera on HTTPS.");
    return;
  }

  try {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const bmp      = await createImageBitmap(file);
    const codes    = await detector.detect(bmp);

    if (!codes.length) { alert("No QR code found in the image."); return; }

    playBeep();
    const text = codes[0].rawValue;

    if (mode === "borrow") {
      alert("Borrow upload: please use the camera scan step.");
      return;
    }
    if (mode === "search") {
      await handleSearchByQrResult(text);
      return;
    }
    await submitReturn(text);
  } catch {
    alert("Failed to scan image QR.");
  } finally {
    event.target.value = "";
  }
}

// ===================================================
// BORROW / RETURN
// ===================================================
let currentBorrowerInfo = null;
let borrowScanStop      = null;
let returnScanStop      = null;

function openBorrowModal() {
  if (!requireLogin()) return;
  document.getElementById("borrowFormStep").style.display   = "block";
  document.getElementById("borrowScanStep").style.display   = "none";
  document.getElementById("borrowResultStep").style.display = "none";
  document.getElementById("borrowerName").value     = "";
  document.getElementById("borrowerLrn").value      = "";
  document.getElementById("borrowerSection").value  = "";
  document.getElementById("borrowQuantity").value   = "";
  document.getElementById("borrowFormError").textContent = "";
  document.getElementById("borrowScanError").textContent = "";
  showModal("borrowModalOverlay");
}

async function closeBorrowModal() {
  hideModal("borrowModalOverlay");
  if (borrowScanStop) { await borrowScanStop(); borrowScanStop = null; }
}

async function proceedToScan() {
  const name     = sanitizeName(document.getElementById("borrowerName").value.trim());
  const lrn      = sanitizeLRN(document.getElementById("borrowerLrn").value.trim());
  const section  = sanitizeSection(document.getElementById("borrowerSection").value.trim());
  const quantity = parseInt(document.getElementById("borrowQuantity").value.trim(), 10);
  const errorEl  = document.getElementById("borrowFormError");

  if (!isValidName(name))       return (errorEl.textContent = "Enter a valid borrower name.");
  if (!isValidLRN(lrn))         return (errorEl.textContent = "LRN must be exactly 12 digits.");
  if (!isValidSection(section)) return (errorEl.textContent = "Enter a valid section (2–20).");
  if (!quantity || quantity <= 0) return (errorEl.textContent = "Enter a valid quantity.");

  currentBorrowerInfo = { name, lrn, section, quantity };
  document.getElementById("borrowFormStep").style.display = "none";
  document.getElementById("borrowScanStep").style.display = "block";
  document.getElementById("borrowScanError").textContent  = "";
  await startBorrowScan();
}

async function startBorrowScan() {
  if (borrowScanStop) await borrowScanStop();
  const { name, lrn, section, quantity } = currentBorrowerInfo;
  const controller = await startUniversalQrScan(
    "borrowQrReader",
    async (decodedText) => { await submitBorrow(decodedText, name, lrn, section, quantity); },
    (msg) => { document.getElementById("borrowScanError").textContent = msg; }
  );
  borrowScanStop = controller.stop;
}

async function restartBorrowScan() {
  document.getElementById("borrowResultStep").style.display = "none";
  document.getElementById("borrowScanStep").style.display   = "block";
  document.getElementById("borrowScanError").textContent    = "";
  await startBorrowScan();
}

async function submitBorrow(qrText, name, lrn, section, quantity) {
  const errorEl  = document.getElementById("borrowScanError");
  const itemData = safeParseQr(qrText);
  if (!itemData) { errorEl.textContent = "Invalid or unrecognized QR code."; return; }

  const items = safeReadItems();
  const idx   = items.findIndex(it => it.id === itemData.id);
  if (idx === -1)                    { errorEl.textContent = "Item not found in inventory."; return; }
  if (items[idx].quantity < quantity) { errorEl.textContent = "Not enough stock for that quantity."; return; }

  const borrowedItemName = items[idx].name;
  items[idx].quantity   -= quantity;
  writeLS(LS.items, items);

  const session = readLS(LS.session, { loggedIn: false });
  const borrows = safeReadBorrows();
  borrows.push({
    borrowId:       "BORROW-" + Date.now(),
    itemId:         itemData.id,
    itemName:       borrowedItemName,
    borrowerName:   name,
    borrowerLrn:    lrn,
    borrowerSection: section,
    quantity,
    providerName:   typeof session.fullName === "string" ? session.fullName : "Unknown",
    providerLrn:    typeof session.lrn      === "string" ? session.lrn      : "",
    dateBorrowed:   nowISO(),
    dateReturned:   null,
    receiverName:   null,
    receiverLrn:    null
  });
  writeLS(LS.borrows, borrows);
  updateToolboxCounts();

  document.getElementById("borrowScanStep").style.display   = "none";
  document.getElementById("borrowResultStep").style.display = "block";
  document.getElementById("borrowResultContent").innerHTML  = `
    <div class="infoSection">
      <p class="infoLabel">Borrowed</p>
      <p class="infoValue">${escapeHtml(borrowedItemName)} × ${quantity}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Borrower</p>
      <p class="infoValue">${escapeHtml(name)} • LRN: ${escapeHtml(lrn)}</p>
      <p class="infoValue">Section: ${escapeHtml(section)}</p>
    </div>
  `;
}

async function openReturnModal() {
  if (!requireLogin()) return;
  document.getElementById("returnScanStep").style.display   = "block";
  document.getElementById("returnResultStep").style.display = "none";
  document.getElementById("returnScanError").textContent    = "";
  showModal("returnModalOverlay");
  await startReturnScan();
}

async function startReturnScan() {
  if (returnScanStop) await returnScanStop();
  const controller = await startUniversalQrScan(
    "returnQrReader",
    async (decodedText) => { await submitReturn(decodedText); },
    (msg) => { document.getElementById("returnScanError").textContent = msg; }
  );
  returnScanStop = controller.stop;
}

async function restartReturnScan() {
  document.getElementById("returnResultStep").style.display = "none";
  document.getElementById("returnScanStep").style.display   = "block";
  document.getElementById("returnScanError").textContent    = "";
  await startReturnScan();
}

async function closeReturnModal() {
  hideModal("returnModalOverlay");
  if (returnScanStop) { await returnScanStop(); returnScanStop = null; }
}

async function submitReturn(qrText) {
  const errorEl  = document.getElementById("returnScanError");
  const itemData = safeParseQr(qrText);
  if (!itemData) { errorEl.textContent = "Invalid or unrecognized QR code."; return; }

  const borrows  = safeReadBorrows();
  const revIndex = [...borrows].reverse().findIndex(b => b.itemId === itemData.id && !b.dateReturned);
  if (revIndex === -1) { errorEl.textContent = "No active borrow record found for this item."; return; }

  const realIndex = borrows.length - 1 - revIndex;
  const session   = readLS(LS.session, { loggedIn: false });

  borrows[realIndex].dateReturned = nowISO();
  borrows[realIndex].receiverName = typeof session.fullName === "string" ? session.fullName : "Unknown";
  borrows[realIndex].receiverLrn  = typeof session.lrn      === "string" ? session.lrn      : "";
  writeLS(LS.borrows, borrows);

  const items = safeReadItems();
  const idx   = items.findIndex(it => it.id === itemData.id);
  if (idx !== -1) {
    items[idx].quantity += Number(borrows[realIndex].quantity);
    writeLS(LS.items, items);
  }

  const rb = borrows[realIndex];
  document.getElementById("returnScanStep").style.display   = "none";
  document.getElementById("returnResultStep").style.display = "block";
  document.getElementById("returnResultContent").innerHTML  = `
    <div class="infoSection">
      <p class="infoLabel">Returned</p>
      <p class="infoValue">${escapeHtml(rb.itemName)} × ${rb.quantity}</p>
    </div>
    <div class="infoSection">
      <p class="infoLabel">Received By</p>
      <p class="infoValue">${escapeHtml(rb.receiverName)} • LRN: ${escapeHtml(rb.receiverLrn)}</p>
      <p class="infoValue">${new Date(rb.dateReturned).toLocaleString()}</p>
    </div>
  `;
}

// ===================================================
// GUEST "BORROW NOW" NOTICE
// Guests can't self-serve a borrow/return — this just points them
// to in-person help instead of opening the real borrow flow.
// ===================================================
function openGuestBorrowModal() {
  showModal("guestBorrowModalOverlay");
  closeMenuPanel();
}

function closeGuestBorrowModal() {
  hideModal("guestBorrowModalOverlay");
}

// ===================================================
// ITEM CAROUSEL — 20 most recently added items, shown to
// guests and logged-in users alike. Auto-advances, but a
// manual swipe/scroll/wheel pauses auto-advance for a while.
// ===================================================
let carouselAutoTimer   = null;
let carouselPauseTimer  = null;
let carouselIndex       = 0;

function renderItemCarousel() {
  const track = document.getElementById("itemCarouselTrack");
  const dots  = document.getElementById("itemCarouselDots");
  if (!track || !dots) return;

  const items = safeReadItems()
    .slice()
    .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
    .slice(0, 20);

  if (!items.length) {
    track.innerHTML = `<div class="itemCarouselEmpty">We're Sorry. No items added yet, check back soon.</div>`;
    dots.innerHTML  = "";
    stopCarouselAuto();
    return;
  }

  track.innerHTML = items.map(item => {
    const bg = item.imageDataUrl
      ? `background-image:url('${item.imageDataUrl}');`
      : `background-color:#3a3a46;`;
    return `
      <div class="itemCarouselSlide" style="${bg}">
        <div class="itemCarouselSlide__overlay">
          <p class="itemCarouselSlide__name">${escapeHtml(item.name)}</p>
          ${item.description ? `<p class="itemCarouselSlide__desc">${escapeHtml(item.description)}</p>` : ""}
        </div>
      </div>
    `;
  }).join("");

  dots.innerHTML = items.map((_, i) => `<span class="itemCarouselDot${i === 0 ? " active" : ""}" data-index="${i}"></span>`).join("");
  dots.querySelectorAll(".itemCarouselDot").forEach(dot => {
    dot.addEventListener("click", () => goToCarouselSlide(Number(dot.dataset.index)));
  });

  carouselIndex = 0;
  startCarouselAuto();
}

function goToCarouselSlide(index) {
  const track  = document.getElementById("itemCarouselTrack");
  const slides = track?.querySelectorAll(".itemCarouselSlide");
  if (!slides || !slides.length) return;
  carouselIndex = ((index % slides.length) + slides.length) % slides.length;
  track.scrollTo({ left: track.clientWidth * carouselIndex, behavior: "smooth" });
  updateCarouselDots();
}

function updateCarouselDots() {
  document.querySelectorAll("#itemCarouselDots .itemCarouselDot").forEach((dot, i) => {
    dot.classList.toggle("active", i === carouselIndex);
  });
}

function startCarouselAuto() {
  stopCarouselAuto();
  carouselAutoTimer = setInterval(() => {
    const track = document.getElementById("itemCarouselTrack");
    const count = track ? track.querySelectorAll(".itemCarouselSlide").length : 0;
    if (!count) return;
    goToCarouselSlide((carouselIndex + 1) % count);
  }, 4000);
}

function stopCarouselAuto() {
  if (carouselAutoTimer) { clearInterval(carouselAutoTimer); carouselAutoTimer = null; }
}

function pauseCarouselAutoTemporarily() {
  stopCarouselAuto();
  if (carouselPauseTimer) clearTimeout(carouselPauseTimer);
  carouselPauseTimer = setTimeout(startCarouselAuto, 6000);
}

function initCarouselManualControls() {
  const track = document.getElementById("itemCarouselTrack");
  if (!track) return;

  ["pointerdown", "touchstart", "wheel"].forEach(evt => {
    track.addEventListener(evt, pauseCarouselAutoTemporarily, { passive: true });
  });

  let scrollDebounce = null;
  track.addEventListener("scroll", () => {
    clearTimeout(scrollDebounce);
    scrollDebounce = setTimeout(() => {
      if (!track.clientWidth) return;
      const idx = Math.round(track.scrollLeft / track.clientWidth);
      if (idx !== carouselIndex) { carouselIndex = idx; updateCarouselDots(); }
    }, 100);
  }, { passive: true });
}

// ===================================================
// RATINGS & TESTIMONIALS
//
// Storage layer today = localStorage (see LS.ratings above), but every
// read/write goes through this RatingsAPI wrapper so swapping to a real
// backend later only means rewriting the bodies below — nothing that
// calls RatingsAPI.* has to change. Drop-in backend shape:
//   getAll()  -> GET  /api/ratings          (returns [{id,stars,text,dateAdded}])
//   add(...)  -> POST /api/ratings  {stars,text}
// ===================================================
const RatingsAPI = {
  getAll() {
    // TODO(backend): replace with `return fetch('/api/ratings').then(r => r.json());`
    return safeReadRatings().sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded));
  },

  add(stars, text) {
    // TODO(backend): replace with
    //   return fetch('/api/ratings', {
    //     method: 'POST',
    //     headers: { 'Content-Type': 'application/json' },
    //     body: JSON.stringify({ stars, text })
    //   }).then(r => r.json());
    const rating = {
      id: `rt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      stars: Number(stars),
      text: String(text || "").slice(0, 240),
      dateAdded: nowISO()
    };
    const all = safeReadRatings();
    all.push(rating);
    writeLS(LS.ratings, all);
    return rating;
  },

  getSummary() {
    const all = this.getAll();
    if (!all.length) return { average: 0, count: 0 };
    const total = all.reduce((sum, r) => sum + r.stars, 0);
    return { average: total / all.length, count: all.length };
  }
};

function starString(count) {
  const full = Math.round(count);
  return "★".repeat(full) + "☆".repeat(5 - full);
}

let testimonialAutoTimer = null;
let testimonialIndex     = 0;

function renderTestimonialSummary() {
  const { average, count } = RatingsAPI.getSummary();
  const scoreEl = document.getElementById("testimonialAvgScore");
  const starsEl = document.getElementById("testimonialAvgStars");
  const countEl = document.getElementById("testimonialCount");
  if (scoreEl) scoreEl.textContent = average.toFixed(1);
  if (starsEl) starsEl.textContent = starString(average);
  if (countEl) countEl.textContent = `${count} rating${count === 1 ? "" : "s"}`;
}

function renderTestimonials() {
  const track = document.getElementById("testimonialCarouselTrack");
  const dots  = document.getElementById("testimonialDots");
  if (!track || !dots) return;

  renderTestimonialSummary();

  const ratings = RatingsAPI.getAll();

  if (!ratings.length) {
    track.innerHTML = `<div class="testimonialSlide"><p class="testimonialEmpty">Be the first to rate our website!</p></div>`;
    dots.innerHTML  = "";
    stopTestimonialAuto();
    return;
  }

  track.innerHTML = ratings.map(r => `
    <div class="testimonialSlide">
      <div class="testimonialSlide__stars" aria-hidden="true">${starString(r.stars)}</div>
      ${r.text ? `<p class="testimonialSlide__text">"${escapeHtml(r.text)}"</p>` : ""}
      <p class="testimonialSlide__author">— Anonymous</p>
    </div>
  `).join("");

  dots.innerHTML = ratings.map((_, i) => `<span class="testimonialDot${i === 0 ? " active" : ""}" data-index="${i}"></span>`).join("");
  dots.querySelectorAll(".testimonialDot").forEach(dot => {
    dot.addEventListener("click", () => goToTestimonialSlide(Number(dot.dataset.index)));
  });

  testimonialIndex = 0;
  startTestimonialAuto();
}

function goToTestimonialSlide(index) {
  const track  = document.getElementById("testimonialCarouselTrack");
  const slides = track?.querySelectorAll(".testimonialSlide");
  if (!slides || !slides.length) return;
  testimonialIndex = ((index % slides.length) + slides.length) % slides.length;
  track.scrollTo({ left: track.clientWidth * testimonialIndex, behavior: "smooth" });
  document.querySelectorAll("#testimonialDots .testimonialDot").forEach((dot, i) => {
    dot.classList.toggle("active", i === testimonialIndex);
  });
}

function startTestimonialAuto() {
  stopTestimonialAuto();
  testimonialAutoTimer = setInterval(() => {
    const track = document.getElementById("testimonialCarouselTrack");
    const count = track ? track.querySelectorAll(".testimonialSlide").length : 0;
    if (!count) return;
    goToTestimonialSlide((testimonialIndex + 1) % count);
  }, 5000);
}

function stopTestimonialAuto() {
  if (testimonialAutoTimer) { clearInterval(testimonialAutoTimer); testimonialAutoTimer = null; }
}

// ---------- "Rate this website" modal + star picker ----------
let selectedRatingStars = 0;

function paintStarPicker(value) {
  document.querySelectorAll("#starPicker .starPicker__star").forEach(star => {
    star.classList.toggle("is-filled", Number(star.dataset.value) <= value);
  });
}

function initStarPicker() {
  const picker = document.getElementById("starPicker");
  if (!picker) return;
  picker.querySelectorAll(".starPicker__star").forEach(star => {
    star.addEventListener("click", () => {
      selectedRatingStars = Number(star.dataset.value);
      paintStarPicker(selectedRatingStars);
    });
    star.addEventListener("mouseenter", () => paintStarPicker(Number(star.dataset.value)));
    star.addEventListener("mouseleave", () => paintStarPicker(selectedRatingStars));
  });
}

function openRatingModal() {
  selectedRatingStars = 0;
  paintStarPicker(0);
  const textInput = document.getElementById("ratingTextInput");
  const errorEl   = document.getElementById("ratingFormError");
  if (textInput) textInput.value = "";
  if (errorEl)   errorEl.textContent = "";
  showModal("ratingModalOverlay");
}

function closeRatingModal() {
  hideModal("ratingModalOverlay");
}

function submitRating() {
  const errorEl = document.getElementById("ratingFormError");
  if (!selectedRatingStars) {
    if (errorEl) errorEl.textContent = "Please select a star rating.";
    return;
  }
  const text = document.getElementById("ratingTextInput").value.trim().slice(0, 240);
  RatingsAPI.add(selectedRatingStars, text);
  closeRatingModal();
  renderTestimonials();
}

// ===================================================
// SAMPLE ITEM MARQUEE — 20 self-contained icon "photos"
// (inline SVG, no external files/network needed) so the
// strip shows a real picture per item instead of a text
// pill. Every icon shares the same 64x64 canvas, so they
// all come out a uniform size no matter what they draw.
// ===================================================
// Point each `src` at your own image file. Drop your files in an
// img/marquee/ folder (or wherever you like) and update the paths.
const MARQUEE_ITEMS = [
  { name: "Screwdriver",        src: "https://tse2.mm.bing.net/th/id/OIP.BmunNsrX4D05CHM8WqFHBAAAAA?r=0&w=458&h=458&rs=1&pid=ImgDetMain&o=7&rm=3" },
  { name: "LAN Cable Tester",   src: "https://megacompuworldjaipur.com/image/cache/catalog/Product/Cable%20and%20Connector/Multybyte/NEW%20PICS/22%20LAN%20NETWORK%20CABLE%20TESTER-1-1500x997.jpg" },
  { name: "Drill Set",          src: "https://i5.walmartimages.com/seo/STROTON-Cobalt-Drill-Bit-Set-1-16-1-2-17PCS-M35-HSS-Heavy-Duty-Drill-Bits-for-Stainless-Steel-and-Hard-Metal_a7f39e3d-dce5-41f4-810d-703e4e20b289.86616b0bdd53dc112e8b895a60178ad2.jpeg" },
  { name: "Punch Down Tool",    src: "https://www.cablesdirect.co.uk/images/newlink-adjustable-impact-punch-down-tool-p2350-6068_image.jpg" },
  { name: "Crimping Tool",      src: "https://media.karousell.com/media/photos/products/2021/7/23/lan_cable_socket_clamp_c013_1627009674_87531634" },
  { name: "Wire Stripper",      src: "https://jonard.com/sites/default/files/product_files/JPG%20(High%20Resolution)%20-%20JIC-1626_0.jpg" },
  { name: "Multimeter",         src: "https://rukminim1.flixcart.com/image/832/832/xif0q/multimeter/o/r/4/2000-digital-pocket-multimeter-assorted-digital-multimeter-original-imagkngh4xepgteq.jpeg?q=70" },
  { name: "Wrench",             src: "https://img.drz.lazcdn.com/static/bd/p/2f751bc2db4ed23fdcee8e74cf4c9ecf.jpg_720x720q80.jpg" },
  { name: "Pliers",             src: "https://static.grainger.com/rp/s/is/image/Grainger/4YT03_AS01?$adapimg$&hei=536&wid=536" },
  { name: "Hammer",             src: "https://i5.walmartimages.com/asr/50c2fd0d-cde6-4fa6-9387-ebdecd1a97ee.55469b3b129d445317bc77805400116e.jpeg" },
  { name: "Tape Measure",       src: "https://5.imimg.com/data5/SELLER/Default/2022/7/HG/GG/XX/125048506/f6963648-01-500x500.webp" },
  { name: "Utility Knife",      src: "https://nabatechshop.com/wp-content/uploads/2023/05/Solder-Sucker-desoldering-pump.jpg" },
  { name: "Soldering Iron",     src: "https://cdn11.bigcommerce.com/s-ndcz45uza6/images/stencil/640w/products/4118/8869/Green-60W-adjustable-soldering-iron-420-42-113__68382.1649857113.jpg?c=2" },
  { name: "Flashlight",         src: "https://image.made-in-china.com/2f0j00yTYRHGvKaEbn/Hand-Tools-Cr-V-Steel-5-75mm-Straight-Flat-Slotted-Head-Screwdriver.jpg" },
  { name: "Tool Box",           src: "https://ae01.alicdn.com/kf/H057cb6fea52640acae12c2cc5d09572cv.jpg" }
];

function renderMarquee() {
  const groups = document.querySelectorAll("#itemMarquee .marquee__group");
  if (!groups.length) return;

  const html = MARQUEE_ITEMS.map(item => `
    <div class="marqueeItem" title="${item.name}">
      <img src="${item.src}" alt="${item.name}" loading="lazy">
    </div>
  `).join("");

  groups.forEach(g => { g.innerHTML = html; });
}

// ===================================================
// INTRO PARAGRAPH TYPEWRITER — types the paragraph out
// character by character. Runs fresh on every page load
// (nothing is stored), and starts the moment the
// paragraph scrolls into view.
// ===================================================
function initTypedParagraph() {
  const el = document.getElementById("introParagraph");
  if (!el) return;

  const fullText = el.textContent.trim().replace(/\s+/g, " ");
  el.textContent = "";

  const cursor = document.createElement("span");
  cursor.className = "typedCursor";
  cursor.textContent = "|";
  el.appendChild(cursor);

  let i = 0;
  function typeNext() {
    if (i < fullText.length) {
      cursor.insertAdjacentText("beforebegin", fullText.charAt(i));
      i++;
      setTimeout(typeNext, 22);
    } else {
      setTimeout(() => cursor.remove(), 900);
    }
  }

  if (!("IntersectionObserver" in window)) {
    typeNext();
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        typeNext();
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.2 });

  observer.observe(el);
}

// ===================================================
// FADE-IN ON SCROLL — reveals .revealOnScroll elements
// (toolboxes, dividers, footer, etc.) as they enter view.
// ===================================================
function initScrollReveal() {
  const targets = document.querySelectorAll(".revealOnScroll");
  if (!targets.length) return;

  if (!("IntersectionObserver" in window)) {
    targets.forEach(t => t.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });

  targets.forEach(t => observer.observe(t));
}

// ===================================================
// FOOTER — collapsible "About this website" / "Legal"
// ===================================================
function toggleFooterSection(panelId, btn) {
  const panel = document.getElementById(panelId);
  if (!panel) return;
  const isOpen = panel.classList.toggle("is-open");
  if (btn) btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

// ===================================================
// INIT
// ===================================================
document.addEventListener("DOMContentLoaded", function() {
  updateFormLabels();
  const s = readLS(LS.session, null);
  if (!s) writeLS(LS.session, { loggedIn: false });
  updateMenuUI();
  updateToolboxCounts();
  renderItemCarousel();
  initCarouselManualControls();
  renderTestimonials();
  initStarPicker();
  renderMarquee();
  initTypedParagraph();
  initScrollReveal();

  const yearLegal  = document.getElementById("footerYearLegal");
  const yearBottom = document.getElementById("footerYearBottom");
  const year       = new Date().getFullYear();
  if (yearLegal)  yearLegal.textContent  = year;
  if (yearBottom) yearBottom.textContent = year;
});
