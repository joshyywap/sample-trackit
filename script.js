// ===============================
// TrackIT - PURE FRONTEND (no API)
// Universal QR scanner:
// - Prefer BarcodeDetector (Chrome/Edge support)
// - Fallback to html5-qrcode
// - Fallback to Upload Image
// ===============================

// ---------- localStorage keys ----------
const LS = {
  session: "trackit_session",
  users: "trackit_users",
  items: "trackit_items",
  borrows: "trackit_borrows",
  lostFound: "trackit_lostfound"
};

// ---------- 5 fixed toolbox categories ----------
// Rename these anytime - the "name" field is all that shows in item detail views.
const TOOLBOXES = [
  { id: 1, name: "Toolbox 1", icon: "" },
  { id: 2, name: "Toolbox 2", icon: "" },
  { id: 3, name: "Toolbox 3", icon: "" },
  { id: 4, name: "Toolbox 4", icon: "" },
  { id: 5, name: "RANDOM ITEMs", icon: "" },
];

function toolboxName(id) {
  const t = TOOLBOXES.find(t => t.id === Number(id));
  return t ? t.name : "Unassigned";
}

// ---------- helpers ----------
function readLS(key, fallback) {
  try {
    const v = JSON.parse(localStorage.getItem(key));
    if (v === null || v === undefined) return fallback;
    if (Array.isArray(fallback) && !Array.isArray(v)) return fallback;
    return v;
  } catch {
    return fallback;
  }
}
function writeLS(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}
function nowISO() {
  return new Date().toISOString();
}
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function requireLogin() {
  const session = readLS(LS.session, { loggedIn: false });
  if (!session.loggedIn) {
    alert("Please login first.");
    return false;
  }
  return true;
}
function closeMenuPanel() {
  const menuToggle = document.getElementById("menuToggle");
  if (menuToggle) menuToggle.checked = true;
}

// ---------- generic modal open/close ----------
// Locks page scroll using the "position: fixed" technique applied directly
// via JS inline styles (not a CSS class) so it works even on iOS Safari,
// where `overflow:hidden` alone often still lets the background scroll,
// and so it can't silently fail just because a cached stylesheet is stale.
// The white/blur backdrop itself is CSS (.modal-overlay) - purely visual,
// not required for the scroll-lock to function.
let savedScrollY = 0;

function showModal(overlayId) {
  document.getElementById(overlayId).style.display = "flex";

  savedScrollY = window.scrollY || window.pageYOffset || 0;
  document.body.style.position = "fixed";
  document.body.style.top = `-${savedScrollY}px`;
  document.body.style.left = "0";
  document.body.style.right = "0";
  document.body.style.width = "100%";
}

function hideModal(overlayId) {
  document.getElementById(overlayId).style.display = "none";

  document.body.style.position = "";
  document.body.style.top = "";
  document.body.style.left = "";
  document.body.style.right = "";
  document.body.style.width = "";
  window.scrollTo(0, savedScrollY);
}

// ===================================================
// AUTH FORM STATE
// ===================================================
let authMode = "login";

const fullNameInput = document.getElementById("fullName");
const lrnInput = document.getElementById("lrn");
const passwordInput = document.getElementById("password");
const sectionInput = document.getElementById("section");
const sectionRow = document.getElementById("sectionRow");
const authError = document.getElementById("authError");
const formHeading = document.getElementById("formHeading");
const signupPrompt = document.getElementById("signupPrompt");
const toggleModeLink = document.getElementById("toggleModeLink");

function sanitizeName(raw) { return raw.replace(/[^A-Za-z ]/g, "").slice(0, 50).trim(); }
function sanitizeLRN(raw) { return raw.replace(/[^0-9]/g, "").slice(0, 12); }
function sanitizeSection(raw) { return raw.replace(/[^A-Za-z0-9\- ]/g, "").slice(0, 20).trim(); }

function isValidName(v) { return /^[A-Za-z ]{2,50}$/.test(v); }
function isValidLRN(v) { return /^[0-9]{12}$/.test(v); }
function isValidPassword(v) { return v.length >= 8 && v.length <= 64; }
function isValidSection(v) { return /^[A-Za-z0-9\- ]{2,20}$/.test(v); }

toggleModeLink?.addEventListener("click", function (e) {
  e.preventDefault();
  authMode = authMode === "login" ? "register" : "login";
  updateFormLabels();
});

document.getElementById("backToChoiceLink")?.addEventListener("click", function (e) {
  e.preventDefault();
  showAuthChoice();
});

function updateFormLabels() {
  if (authMode === "login") {
    formHeading.textContent = "Login";
    signupPrompt.textContent = "Don't have any account?";
    toggleModeLink.textContent = "Sign up";
    sectionRow.style.display = "none";
  } else {
    formHeading.textContent = "Register";
    signupPrompt.textContent = "Already have an account?";
    toggleModeLink.textContent = "Login";
    sectionRow.style.display = "flex";
  }
  authError.textContent = "";
}

function showAuthForm(mode) {
  authMode = mode;
  document.getElementById("authChoice").style.display = "none";
  document.getElementById("authFormWrapper").style.display = "block";
  updateFormLabels();
}

function showAuthChoice() {
  document.getElementById("authChoice").style.display = "block";
  document.getElementById("authFormWrapper").style.display = "none";
  authError.textContent = "";
}

function togglePasswordVisibility() {
  const passwordField = document.getElementById("password");
  const icon = document.getElementById("togglePasswordIcon");
  if (!passwordField) return;
  if (passwordField.type === "password") {
    passwordField.type = "text";
    if (icon) icon.style.opacity = "1";
  } else {
    passwordField.type = "password";
    if (icon) icon.style.opacity = "0.6";
  }
}

// ===================================================
// REGISTER / LOGIN — localStorage
// ===================================================
async function handleAuthSubmit(e) {
  e.preventDefault();
  authError.textContent = "";

  const rawName = fullNameInput.value.trim();
  const rawLRN = lrnInput.value.trim();
  const password = passwordInput.value;

  const cleanName = sanitizeName(rawName);
  const cleanLRN = sanitizeLRN(rawLRN);

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

  const users = readLS(LS.users, []);

  if (authMode === "register") {
    const sectionClean = sanitizeSection(sectionInput.value.trim());
    if (!isValidSection(sectionClean)) {
      authError.textContent = "Section must be 2–20 chars (letters/numbers/-/space).";
      return;
    }

    const exists = users.some(u => u.lrn === cleanLRN);
    if (exists) {
      authError.textContent = "LRN already registered. Please login.";
      return;
    }

    users.push({ fullName: cleanName, lrn: cleanLRN, password, section: sectionClean });
    writeLS(LS.users, users);

    writeLS(LS.session, { loggedIn: true, fullName: cleanName, lrn: cleanLRN });
    updateMenuUI();
  } else {
    const user = users.find(u => u.lrn === cleanLRN);
    if (!user || user.password !== password) {
      authError.textContent = "Invalid LRN or password.";
      return;
    }

    writeLS(LS.session, { loggedIn: true, fullName: user.fullName, lrn: user.lrn });
    updateMenuUI();
  }

  fullNameInput.value = "";
  lrnInput.value = "";
  passwordInput.value = "";
  if (sectionInput) sectionInput.value = "";
}

// ===================================================
// LOGOUT (now with confirmation)
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
  const session = readLS(LS.session, { loggedIn: false });
  const loggedIn = !!session.loggedIn;
  const fullName = session.fullName || "Guest";
  const lrn = session.lrn || "";

  document.getElementById("usrName").textContent = fullName;
  document.getElementById("usrLrn").textContent = lrn;

  document.getElementById("authButtons").style.display = loggedIn ? "none" : "block";
  document.getElementById("accountButtons").style.display = loggedIn ? "block" : "none";

  // Borrow/Return only visible to logged-in accounts.
  // Set directly via inline style (not just a CSS class) so this can't be
  // silently defeated by a stale/cached style.css - inline styles always
  // win regardless of what stylesheet the browser currently has loaded.
  const bottone1 = document.getElementById("bottone1");
  const bottone2 = document.getElementById("bottone2");
  if (bottone1) bottone1.style.display = loggedIn ? "" : "none";
  if (bottone2) bottone2.style.display = loggedIn ? "" : "none";

  if (!loggedIn) showAuthChoice();
}

// ===================================================
// TOOLBOX GRID (home page)
// ===================================================
function updateToolboxCounts() {
  const items = readLS(LS.items, []);
  TOOLBOXES.forEach(t => {
    const count = items.filter(i => Number(i.toolbox) === t.id).length;
    const el = document.getElementById(`toolboxCount${t.id}`);
    if (el) el.textContent = `${count} item${count === 1 ? "" : "s"}`;
  });
}

// ===================================================
// TOOLBOX VIEW MODAL (browse items inside one toolbox)
// ===================================================
let currentToolboxViewId = null;

function openToolboxView(id) {
  currentToolboxViewId = id;
  document.getElementById("toolboxViewTitle").textContent = toolboxName(id);
  document.getElementById("toolboxSearchInput").value = "";
  renderToolboxItems();
  showModal("toolboxViewModalOverlay");
}

function closeToolboxView() {
  hideModal("toolboxViewModalOverlay");
  currentToolboxViewId = null;
}

function renderToolboxItems() {
  const container = document.getElementById("toolboxItemList");
  const search = document.getElementById("toolboxSearchInput").value.trim().toLowerCase();

  const items = readLS(LS.items, [])
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
// ADD ITEM MODAL — localStorage
// ===================================================
let currentItemId = null;
let addItemImageDataUrl = null;
let selectedToolboxId = null;

function renderToolboxChooser() {
  const wrap = document.getElementById("toolboxChooser");
  wrap.innerHTML = TOOLBOXES.map(t => `
    <div class="toolboxChip${selectedToolboxId === t.id ? " selected" : ""}" onclick="selectToolbox(${t.id})">
      ${escapeHtml(t.name)}
    </div>
  `).join("");
}

function selectToolbox(id) {
  selectedToolboxId = id;
  renderToolboxChooser();
}

function openAddItemModal() {
  if (!requireLogin()) return;

  document.getElementById("itemName").value = "";
  document.getElementById("itemQuantity").value = "";
  document.getElementById("itemImage").value = "";
  document.getElementById("itemImagePreview").style.display = "none";
  document.getElementById("qrCodeContainer").innerHTML = "";
  document.getElementById("saveItemBtn").style.display = "none";
  document.getElementById("itemFormError").textContent = "";

  selectedToolboxId = null;
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
  const now = new Date();
  const datePart =
    now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, "0") +
    String(now.getDate()).padStart(2, "0");
  const timePart =
    String(now.getHours()).padStart(2, "0") +
    String(now.getMinutes()).padStart(2, "0") +
    String(now.getSeconds()).padStart(2, "0");
  const randomPart = Math.floor(100 + Math.random() * 900);
  return `ITEM-${datePart}-${timePart}-${randomPart}`;
}

function previewItemImage(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    addItemImageDataUrl = e.target.result;
    const preview = document.getElementById("itemImagePreview");
    preview.src = addItemImageDataUrl;
    preview.style.display = "block";
  };
  reader.readAsDataURL(file);
}

function generateItemQR() {
  const name = document.getElementById("itemName").value.trim();
  const quantity = document.getElementById("itemQuantity").value.trim();
  const errorEl = document.getElementById("itemFormError");
  errorEl.textContent = "";

  if (!selectedToolboxId) return (errorEl.textContent = "Please select a toolbox first.");
  if (!name) return (errorEl.textContent = "Please enter the item name first.");
  if (!quantity || Number(quantity) <= 0) return (errorEl.textContent = "Please enter a valid quantity.");

  const qrData = JSON.stringify({ id: currentItemId, name });
  const qrContainer = document.getElementById("qrCodeContainer");
  qrContainer.innerHTML = "";
  new QRCode(qrContainer, { text: qrData, width: 150, height: 150 });

  document.getElementById("saveItemBtn").style.display = "block";
}

async function saveItem() {
  const name = document.getElementById("itemName").value.trim();
  const quantity = Number(document.getElementById("itemQuantity").value.trim());
  const errorEl = document.getElementById("itemFormError");
  errorEl.textContent = "";

  if (!selectedToolboxId) return (errorEl.textContent = "Please select a toolbox.");
  if (!name) return (errorEl.textContent = "Item name is required.");
  if (!quantity || quantity <= 0) return (errorEl.textContent = "Quantity must be at least 1.");

  const items = readLS(LS.items, []);
  items.push({
    id: currentItemId,
    name,
    quantity,
    toolbox: selectedToolboxId,
    imageDataUrl: addItemImageDataUrl || null,
    dateAdded: nowISO()
  });
  writeLS(LS.items, items);

  updateToolboxCounts();
  closeAddItemModal();
}

// ===================================================
// DELETE ITEM MODAL
// ===================================================
function openDeleteItemModal() {
  if (!requireLogin()) return;
  document.getElementById("deleteSearchInput").value = "";
  document.getElementById("deleteItemError").textContent = "";
  renderDeleteItemList();
  showModal("deleteItemModalOverlay");
  closeMenuPanel();
}

function closeDeleteItemModal() {
  hideModal("deleteItemModalOverlay");
}

function renderDeleteItemList() {
  const container = document.getElementById("deleteItemList");
  const search = document.getElementById("deleteSearchInput").value.trim().toLowerCase();

  const items = readLS(LS.items, [])
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
      <button class="deleteBtn" onclick="confirmDeleteItem('${item.id}')">Delete</button>
    </div>
  `).join("");
}

function confirmDeleteItem(id) {
  const errorEl = document.getElementById("deleteItemError");
  errorEl.textContent = "";

  const borrows = readLS(LS.borrows, []);
  const activeBorrow = borrows.find(b => b.itemId === id && !b.dateReturned);
  if (activeBorrow) {
    errorEl.textContent = "Cannot delete: this item is currently borrowed.";
    return;
  }

  if (!confirm("Delete this item permanently?")) return;

  let items = readLS(LS.items, []);
  items = items.filter(i => i.id !== id);
  writeLS(LS.items, items);

  renderDeleteItemList();
  updateToolboxCounts();
}

// ===================================================
// LOST AND FOUND MODAL (replaces old Missing Items)
// ===================================================
let selectedLostStatus = "lost";

function selectLostStatus(status) {
  selectedLostStatus = status;
  document.querySelectorAll("#lostStatusChooser .toolboxChip").forEach(chip => {
    chip.classList.toggle("selected", chip.dataset.status === status);
  });
}

function openLostFoundModal() {
  if (!requireLogin()) return;

  document.getElementById("lostItemName").value = "";
  document.getElementById("lostDescription").value = "";
  document.getElementById("lostFoundError").textContent = "";
  selectLostStatus("lost");

  renderLostFoundList();
  showModal("lostFoundModalOverlay");
  closeMenuPanel();
}

function closeLostFoundModal() {
  hideModal("lostFoundModalOverlay");
}

async function submitLostFound() {
  const errorEl = document.getElementById("lostFoundError");
  errorEl.textContent = "";

  const name = document.getElementById("lostItemName").value.trim();
  const description = document.getElementById("lostDescription").value.trim();

  if (!name || name.length > 60) {
    errorEl.textContent = "Please enter a valid item name (max 60 characters).";
    return;
  }
  if (description.length > 100) {
    errorEl.textContent = "Description must be under 100 characters.";
    return;
  }

  const session = readLS(LS.session, { loggedIn: false });

  const entries = readLS(LS.lostFound, []);
  entries.push({
    id: "LF-" + Date.now(),
    itemName: name,
    description,
    status: selectedLostStatus,
    reportedBy: session.fullName || "Unknown",
    reportedByLrn: session.lrn || "",
    dateReported: nowISO()
  });
  writeLS(LS.lostFound, entries);

  document.getElementById("lostItemName").value = "";
  document.getElementById("lostDescription").value = "";
  renderLostFoundList();
}

function renderLostFoundList() {
  const container = document.getElementById("lostFoundList");
  const entries = readLS(LS.lostFound, [])
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
// LIST OF BORROWER MODAL
// ===================================================
function openBorrowerListModal() {
  if (!requireLogin()) return;
  document.getElementById("borrowerSearchInput").value = "";
  renderBorrowerList();
  showModal("borrowerListModalOverlay");
  closeMenuPanel();
}

function closeBorrowerListModal() {
  hideModal("borrowerListModalOverlay");
}

function renderBorrowerList() {
  const container = document.getElementById("borrowerListBox");
  const search = document.getElementById("borrowerSearchInput").value.trim().toLowerCase();

  const borrows = readLS(LS.borrows, [])
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
        <button class="seeInfoBtn" onclick="openBorrowInfo('${b.borrowId}')">See Info</button>
      </div>
    </div>
  `).join("");
}

// ===================================================
// BORROW RECORD INFO MODAL ("See Info")
// ===================================================
function openBorrowInfo(borrowId) {
  const borrows = readLS(LS.borrows, []);
  const b = borrows.find(x => x.borrowId === borrowId);
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

function closeBorrowInfo() {
  hideModal("borrowInfoModalOverlay");
}

// ===================================================
// INVENTORY MODAL — localStorage
// ===================================================
async function openInventoryModal() {
  if (!requireLogin()) return;
  showModal("inventoryModalOverlay");
  closeMenuPanel();
  await loadInventory();
}

function closeInventoryModal() {
  hideModal("inventoryModalOverlay");
}

async function loadInventory() {
  const container = document.getElementById("inventoryList");
  const items = readLS(LS.items, []).sort((a, b) => a.name.localeCompare(b.name));

  if (!items.length) {
    container.innerHTML = `<p class="emptyMsg">No items in inventory.</p>`;
    return;
  }

  container.innerHTML = items.map(item => {
    const img = item.imageDataUrl
      ? `<img src="${item.imageDataUrl}" style="width:55px; height:55px; object-fit:cover; border-radius:8px;">`
      : `<div style="width:55px; height:55px; background:#f0f0f0; border-radius:8px;"></div>`;

    return `
      <div class="itemRow">
        ${img}
        <div class="itemInfo">
          <p class="name">${escapeHtml(item.name)}</p>
          <p class="meta">${escapeHtml(toolboxName(item.toolbox))} • Added: ${new Date(item.dateAdded).toLocaleDateString()}</p>
        </div>
        <div style="text-align:right;">
          <p style="margin:0; font-weight:bold; font-size:1.1em; color:#1797b8;">${item.quantity}</p>
          <p style="margin:0; font-size:.7em; color:#888;">in stock</p>
        </div>
      </div>
    `;
  }).join("");
}

// ===================================================
// UNIVERSAL QR SCANNER
// ===================================================
let borrowScanStop = null;
let returnScanStop = null;

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
  video.style.width = "100%";
  video.style.borderRadius = "10px";
  container.appendChild(video);

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false
    });
  } catch (e) {
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
          onResult(text);
          return;
        }
      } catch {
        // ignore and keep scanning
      }
      requestAnimationFrame(scanLoop);
    };

    requestAnimationFrame(scanLoop);
    return { stop };
  }

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

  if (!("BarcodeDetector" in window)) {
    alert("Upload QR scanning not supported in this browser. Try Chrome/Edge, or use camera on HTTPS.");
    return;
  }

  try {
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const bmp = await createImageBitmap(file);
    const codes = await detector.detect(bmp);

    if (!codes.length) {
      alert("No QR code found in the image.");
      return;
    }

    const text = codes[0].rawValue;

    if (mode === "borrow") {
      alert("Borrow upload: please use the camera scan step (or we can modify to support upload borrow).");
      return;
    }

    await submitReturn(text);
  } catch (e) {
    alert("Failed to scan image QR.");
  } finally {
    event.target.value = "";
  }
}

// ===================================================
// BORROW / RETURN (localStorage)
// Provider = logged-in account at time of borrow.
// Receiver = logged-in account at time of return.
// Both come from session, NOT from the QR code (the QR only ever
// identifies the item).
// ===================================================
function openBorrowModal() {
  if (!requireLogin()) return;

  document.getElementById("borrowFormStep").style.display = "block";
  document.getElementById("borrowScanStep").style.display = "none";
  document.getElementById("borrowerName").value = "";
  document.getElementById("borrowerLrn").value = "";
  document.getElementById("borrowerSection").value = "";
  document.getElementById("borrowQuantity").value = "";
  document.getElementById("borrowFormError").textContent = "";
  document.getElementById("borrowScanError").textContent = "";

  showModal("borrowModalOverlay");
}

async function closeBorrowModal() {
  hideModal("borrowModalOverlay");
  if (borrowScanStop) {
    await borrowScanStop();
    borrowScanStop = null;
  }
}

async function proceedToScan() {
  const name = document.getElementById("borrowerName").value.trim();
  const lrn = document.getElementById("borrowerLrn").value.trim();
  const section = document.getElementById("borrowerSection").value.trim();
  const quantity = Number(document.getElementById("borrowQuantity").value.trim());
  const errorEl = document.getElementById("borrowFormError");

  if (!isValidName(name)) return (errorEl.textContent = "Enter a valid borrower name.");
  if (!isValidLRN(lrn)) return (errorEl.textContent = "LRN must be exactly 12 digits.");
  if (!isValidSection(section)) return (errorEl.textContent = "Enter a valid section (2–20).");
  if (!quantity || quantity <= 0) return (errorEl.textContent = "Enter a valid quantity.");

  document.getElementById("borrowFormStep").style.display = "none";
  document.getElementById("borrowScanStep").style.display = "block";
  document.getElementById("borrowScanError").textContent = "";

  if (borrowScanStop) await borrowScanStop();

  const controller = await startUniversalQrScan(
    "borrowQrReader",
    async (decodedText) => {
      await submitBorrow(decodedText, name, lrn, section, quantity);
    },
    (msg) => {
      document.getElementById("borrowScanError").textContent = msg;
    }
  );

  borrowScanStop = controller.stop;
}

async function submitBorrow(qrText, name, lrn, section, quantity) {
  const errorEl = document.getElementById("borrowScanError");

  let itemData;
  try {
    itemData = JSON.parse(qrText);
  } catch {
    errorEl.textContent = "Invalid QR code.";
    return;
  }

  const items = readLS(LS.items, []);
  const idx = items.findIndex(it => it.id === itemData.id);
  if (idx === -1) return (errorEl.textContent = "Item not found in inventory.");
  if (items[idx].quantity < quantity) return (errorEl.textContent = "Not enough stock for that quantity.");

  items[idx].quantity -= quantity;
  writeLS(LS.items, items);

  // Provider = whoever is logged in and processing this borrow right now.
  const session = readLS(LS.session, { loggedIn: false });

  const borrows = readLS(LS.borrows, []);
  borrows.push({
    borrowId: "BORROW-" + Date.now(),
    itemId: items[idx].id,
    itemName: items[idx].name,
    borrowerName: name,
    borrowerLrn: lrn,
    borrowerSection: section,
    quantity,
    providerName: session.fullName || "Unknown",
    providerLrn: session.lrn || "",
    dateBorrowed: nowISO(),
    dateReturned: null,
    receiverName: null,
    receiverLrn: null
  });
  writeLS(LS.borrows, borrows);

  alert("Item borrowed successfully!");
  await closeBorrowModal();
}

async function openReturnModal() {
  if (!requireLogin()) return;

  document.getElementById("returnScanError").textContent = "";

  if (returnScanStop) await returnScanStop();

  showModal("returnModalOverlay");

  const controller = await startUniversalQrScan(
    "returnQrReader",
    async (decodedText) => {
      await submitReturn(decodedText);
    },
    (msg) => {
      document.getElementById("returnScanError").textContent = msg;
    }
  );

  returnScanStop = controller.stop;
}

async function closeReturnModal() {
  hideModal("returnModalOverlay");
  if (returnScanStop) {
    await returnScanStop();
    returnScanStop = null;
  }
}

async function submitReturn(qrText) {
  const errorEl = document.getElementById("returnScanError");

  let itemData;
  try {
    itemData = JSON.parse(qrText);
  } catch {
    errorEl.textContent = "Invalid QR code.";
    return;
  }

  const borrows = readLS(LS.borrows, []);

  const revIndex = [...borrows].reverse().findIndex(b => b.itemId === itemData.id && !b.dateReturned);
  if (revIndex === -1) {
    errorEl.textContent = "No active borrow record found for this item.";
    return;
  }
  const realIndex = borrows.length - 1 - revIndex;

  // Receiver = whoever is logged in and processing this return right now.
  const session = readLS(LS.session, { loggedIn: false });

  borrows[realIndex].dateReturned = nowISO();
  borrows[realIndex].receiverName = session.fullName || "Unknown";
  borrows[realIndex].receiverLrn = session.lrn || "";
  writeLS(LS.borrows, borrows);

  const items = readLS(LS.items, []);
  const idx = items.findIndex(it => it.id === itemData.id);
  if (idx !== -1) {
    items[idx].quantity += Number(borrows[realIndex].quantity);
    writeLS(LS.items, items);
  }

  alert("Item returned successfully!");
  await closeReturnModal();
}

// ===================================================
// INIT
// ===================================================
document.addEventListener("DOMContentLoaded", function () {
  updateFormLabels();
  const s = readLS(LS.session, null);
  if (!s) writeLS(LS.session, { loggedIn: false });
  updateMenuUI();
  updateToolboxCounts();
});
