
const LS = {
session: "trackit_session",
users: "trackit_users",
items: "trackit_items",
borrows: "trackit_borrows"
};

const TOOLBOXES = [
{ id: 1, name: "Toolbox 1", icon: "" },
{ id: 2, name: "Toolbox 2", icon: "" },
{ id: 3, name: "Toolbox 3", icon: "" },
{ id: 4, name: "Toolbox 4", icon: "" },
];

function toolboxName(id) {
const t = TOOLBOXES.find(t => t.id === Number(id));
return t ? t.name : "Unassigned";
}

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

async function logout() {
writeLS(LS.session, { loggedIn: false });
updateMenuUI();
closeMenuPanel();
}

function updateMenuUI() {
const session = readLS(LS.session, { loggedIn: false });
const loggedIn = !!session.loggedIn;
const fullName = session.fullName || "Guest";
const lrn = session.lrn || "";

document.getElementById("usrName").textContent = fullName;
document.getElementById("usrLrn").textContent = lrn;

document.getElementById("authButtons").style.display = loggedIn ? "none" : "block";
document.getElementById("accountButtons").style.display = loggedIn ? "block" : "none";

if (!loggedIn) showAuthChoice();
}

function updateToolboxCounts() {
const items = readLS(LS.items, []);
TOOLBOXES.forEach(t => {
const count = items.filter(i => Number(i.toolbox) === t.id).length;
const el = document.getElementById(`toolboxCount${t.id}`);
if (el) el.textContent = `${count} item${count === 1 ? "" : "s"}`;
});
}

let currentToolboxViewId = null;

function openToolboxView(id) {
currentToolboxViewId = id;
document.getElementById("toolboxViewTitle").textContent = toolboxName(id);
document.getElementById("toolboxSearchInput").value = "";
document.getElementById("toolboxViewModalOverlay").style.display = "flex";
renderToolboxItems();
}

function closeToolboxView() {
document.getElementById("toolboxViewModalOverlay").style.display = "none";
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

let currentItemId = null;
let addItemImageDataUrl = null;
let selectedToolboxId = null;

function renderToolboxChooser() {
const wrap = document.getElementById("toolboxChooser");
wrap.innerHTML = TOOLBOXES.map(t => `
<div class="toolboxChip${selectedToolboxId === t.id ? " selected" : ""}" onclick="selectToolbox(${t.id})">
${t.icon} ${escapeHtml(t.name)}
</div>
`).join("");
}

function selectToolbox(id) {
selectedToolboxId = id;
renderToolboxChooser();
}

function openAddItemModal() {
if (!requireLogin()) return;

document.getElementById("addItemModalOverlay").style.display = "flex";
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

closeMenuPanel();
}

function closeAddItemModal() {
document.getElementById("addItemModalOverlay").style.display = "none";
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

function openDeleteItemModal() {
if (!requireLogin()) return;
document.getElementById("deleteItemModalOverlay").style.display = "flex";
document.getElementById("deleteSearchInput").value = "";
document.getElementById("deleteItemError").textContent = "";
renderDeleteItemList();
closeMenuPanel();
}

function closeDeleteItemModal() {
document.getElementById("deleteItemModalOverlay").style.display = "none";
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

function openMissingItemsModal() {
if (!requireLogin()) return;
document.getElementById("missingItemsModalOverlay").style.display = "flex";
renderMissingItems();
closeMenuPanel();
}

function closeMissingItemsModal() {
document.getElementById("missingItemsModalOverlay").style.display = "none";
}

function renderMissingItems() {
const container = document.getElementById("missingItemsList");

const items = readLS(LS.items, [])
.filter(i => Number(i.quantity) === 0)
.sort((a, b) => a.name.localeCompare(b.name));

if (!items.length) {
container.innerHTML = `<p class="emptyMsg">No missing items. Everything is in stock!</p>`;
return;
}

container.innerHTML = items.map(item => `
<div class="itemRow">
${item.imageDataUrl ? `<img src="${item.imageDataUrl}" class="itemThumb">` : `<div class="itemThumb"></div>`}
<div class="itemInfo">
<p class="name">${escapeHtml(item.name)}</p>
<p class="meta">${escapeHtml(toolboxName(item.toolbox))} • ID: ${escapeHtml(item.id)}</p>
</div>
<span class="statusBadge active">Out of stock</span>
</div>
`).join("");
}

function openBorrowerListModal() {
if (!requireLogin()) return;
document.getElementById("borrowerListModalOverlay").style.display = "flex";
document.getElementById("borrowerSearchInput").value = "";
renderBorrowerList();
closeMenuPanel();
}

function closeBorrowerListModal() {
document.getElementById("borrowerListModalOverlay").style.display = "none";
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
<span class="statusBadge ${b.dateReturned ? "returned" : "active"}">${b.dateReturned ? "Returned" : "Active"}</span>
</div>
`).join("");
}

async function openInventoryModal() {
if (!requireLogin()) return;
document.getElementById("inventoryModalOverlay").style.display = "flex";
closeMenuPanel();
await loadInventory();
}

function closeInventoryModal() {
document.getElementById("inventoryModalOverlay").style.display = "none";
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

function openBorrowModal() {
document.getElementById("borrowModalOverlay").style.display = "flex";
document.getElementById("borrowFormStep").style.display = "block";
document.getElementById("borrowScanStep").style.display = "none";
document.getElementById("borrowerName").value = "";
document.getElementById("borrowerLrn").value = "";
document.getElementById("borrowerSection").value = "";
document.getElementById("borrowQuantity").value = "";
document.getElementById("borrowFormError").textContent = "";
document.getElementById("borrowScanError").textContent = "";
}

async function closeBorrowModal() {
document.getElementById("borrowModalOverlay").style.display = "none";
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

const borrows = readLS(LS.borrows, []);
borrows.push({
borrowId: "BORROW-" + Date.now(),
itemId: items[idx].id,
itemName: items[idx].name,
borrowerName: name,
borrowerLrn: lrn,
borrowerSection: section,
quantity,
dateBorrowed: nowISO(),
dateReturned: null
});
writeLS(LS.borrows, borrows);

alert("Item borrowed successfully!");
await closeBorrowModal();
}

async function openReturnModal() {
document.getElementById("returnModalOverlay").style.display = "flex";
document.getElementById("returnScanError").textContent = "";

if (returnScanStop) await returnScanStop();

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
document.getElementById("returnModalOverlay").style.display = "none";
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

borrows[realIndex].dateReturned = nowISO();
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

document.addEventListener("DOMContentLoaded", function () {
updateFormLabels();
const s = readLS(LS.session, null);
if (!s) writeLS(LS.session, { loggedIn: false });
updateMenuUI();
updateToolboxCounts();
});