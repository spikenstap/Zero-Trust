"use strict";
const $ = (id) => document.getElementById(id);
const roleNames = {doctor: "Врач", nurse: "Медсестра", patient: "Пациент", admin: "Администратор"};
let current = null, observer = null, loginVersion = 0, pollBusy = false, paused = false;
let attackBusy = false, cooldownUntil = 0, auditRetryAt = 0, latestRequests = new Set();
const attackButtons = [...document.querySelectorAll("[data-attack]")];
const userButtons = [...document.querySelectorAll("[data-user]")];

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function feedback(id, text, success = false) {
  const box = $(id); box.textContent = text; box.hidden = !text;
  box.classList.toggle("success", success);
}
async function request(path, {token = current?.access_token, method = "GET", body, night = false} = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (night) headers["X-Demo-Night"] = "1";
  if (body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store"});
  const data = await response.json();
  return {status: response.status, ok: response.ok, data,
    audit: response.headers.get("X-Audit-ID"), requestId: response.headers.get("X-Request-ID"),
    suspicious: response.headers.get("X-Audit-Suspicious") === "true",
    retry: Number(response.headers.get("Retry-After") || 0)};
}
async function login(username) {
  const response = await request("/auth/login", {method: "POST", token: null, body: {username, password: "demo123"}});
  if (!response.ok) throw new Error(response.data.detail || "Не удалось войти");
  return response.data;
}
function describe(response) {
  const detail = typeof response.data.detail === "string" ? response.data.detail : "Запрос обработан";
  return `HTTP ${response.status} · ${detail}${response.audit ? ` · Аудит #${response.audit}` : ""}${response.retry ? ` · Повторите через ${response.retry} с` : ""}`;
}
function setIdentity() {
  userButtons.forEach(b => b.setAttribute("aria-pressed", String(b.dataset.user === current?.user.username)));
  $("session-status").textContent = current ? `${roleNames[current.user.role]} · JWT 15 мин` : "Нет активной сессии";
  $("session-status").className = `badge ${current ? "allow" : "neutral"}`;
  $("identity").textContent = current ? `${current.user.display_name} · ${current.user.username} · ${roleNames[current.user.role]}` : "Войдите, чтобы исследовать политики доступа.";
  $("token-value").textContent = current?.access_token || "Токен ещё не выдан";
  $("token-details").open = false;
  ["logout", "refresh-patients", "open-card"].forEach(id => $(id).disabled = !current);
}
function clearPatients() {
  $("patient-rows").replaceChildren(); $("record").replaceChildren(); $("record").hidden = true;
  $("patient-content").hidden = true; $("patient-empty").hidden = false;
  $("patient-scope").textContent = "Доступ определяется на сервере";
  feedback("patient-feedback", "");
}
async function chooseUser(username) {
  const version = ++loginVersion;
  current = null; setIdentity(); clearPatients();
  userButtons.forEach(b => b.disabled = true);
  feedback("login-feedback", "Выполняется вход…", true);
  try {
    const result = await login(username);
    if (version !== loginVersion) return;
    current = result; setIdentity(); feedback("login-feedback", "");
    await loadPatients();
  } catch (error) { feedback("login-feedback", `Ошибка соединения: ${error.message}`); }
  finally { userButtons.forEach(b => b.disabled = false); }
}
async function loadPatients() {
  if (!current) return;
  const session = current;
  $("refresh-patients").disabled = true;
  $("record").hidden = true;
  try {
    const result = await request("/api/patients", {token: session.access_token, night: $("night-mode").checked});
    if (session !== current) return;
    $("patient-rows").replaceChildren();
    $("patient-content").hidden = !result.ok;
    $("patient-empty").hidden = result.ok || result.status === 403;
    if (!result.ok) { feedback("patient-feedback", describe(result)); return; }
    feedback("patient-feedback", "");
    $("patient-scope").textContent = `${roleNames[session.user.role]} · доступно карт: ${result.data.length}${session.user.role === "nurse" ? " · диагноз и заметки скрыты" : ""}`;
    for (const patient of result.data) {
      const row = element("tr"); row.dataset.id = patient.id;
      const name = element("td"); name.append(element("strong", patient.full_name), element("small", `ID ${String(patient.id).padStart(3, "0")} · ${patient.birth_date}`));
      const doctor = element("td", patient.doctor_name);
      const action = element("td"); const button = element("button", "Открыть");
      button.setAttribute("aria-label", `Открыть карту: ${patient.full_name}`);
      button.addEventListener("click", () => openCard(patient.id)); action.append(button);
      row.append(name, doctor, action); $("patient-rows").append(row);
    }
  } catch (error) { if (session === current) feedback("patient-feedback", `Нет связи с сервером: ${error.message}`); }
  finally { $("refresh-patients").disabled = !current; }
}
async function openCard(id) {
  if (!current) return;
  const session = current;
  $("record").hidden = true; $("open-card").disabled = true;
  try {
    const result = await request(`/api/patients/${id}`, {token: session.access_token, night: $("night-mode").checked});
    if (session !== current) return;
    if (!result.ok) { feedback("patient-feedback", describe(result)); return; }
    feedback("patient-feedback", `200 · Доступ разрешён · Аудит #${result.audit}`, true);
    const p = result.data, card = $("record"); card.replaceChildren();
    const head = element("div", undefined, "record-header");
    head.append(element("h3", p.full_name), element("span", p.medical_fields_masked ? "Общие данные" : "Доступ разрешён", `badge ${p.medical_fields_masked ? "neutral" : "allow"}`));
    const meta = element("div", undefined, "record-meta");
    meta.append(element("span", `Дата рождения: ${p.birth_date}`), element("span", `Группа крови: ${p.blood_group}`));
    const fields = element("dl");
    fields.append(element("dt", "Диагноз"), element("dd", p.diagnosis), element("dt", "Заметки"), element("dd", p.notes));
    card.append(head, meta, fields); card.hidden = false;
    document.querySelectorAll("#patient-rows tr").forEach(row => row.classList.toggle("selected", Number(row.dataset.id) === id));
  } catch (error) { if (session === current) feedback("patient-feedback", `Нет связи с сервером: ${error.message}`); }
  finally { $("open-card").disabled = !current; }
}
function clearAudit() {
  $("audit-rows").replaceChildren(); $("audit-content").hidden = true; $("audit-empty").hidden = false;
  ["count-all", "count-allow", "count-deny", "count-suspicious"].forEach(id => $(id).textContent = "—");
}
function setObserver() {
  $("connect-audit").textContent = observer ? "Отключить admin" : "Подключить admin";
  $("audit-status").textContent = observer ? (paused ? "Обновление на паузе" : "Наблюдатель: admin") : "Наблюдатель отключён";
  $("audit-status").className = `badge ${observer && !paused ? "allow" : "neutral"}`;
  $("pause-audit").disabled = !observer; $("reset-demo").disabled = !observer;
  $("pause-audit").textContent = paused ? "Продолжить" : "Приостановить";
}
async function toggleObserver() {
  if (observer) { observer = null; clearAudit(); setObserver(); return; }
  $("connect-audit").disabled = true;
  try { observer = await login("admin"); paused = false; auditRetryAt = 0; setObserver(); await pollAudit(); }
  catch (error) { feedback("audit-feedback", `Не удалось подключить наблюдателя: ${error.message}`); }
  finally { $("connect-audit").disabled = false; }
}
async function pollAudit() {
  if (!observer || paused || pollBusy || Date.now() < auditRetryAt) return;
  pollBusy = true; const session = observer;
  try {
    const result = await request("/api/audit?limit=100", {token: session.access_token});
    if (session !== observer) return;
    if (!result.ok) {
      feedback("audit-feedback", describe(result));
      if (result.status === 401) { observer = null; clearAudit(); setObserver(); }
      if (result.status === 429) auditRetryAt = Date.now() + result.retry * 1000;
      return;
    }
    feedback("audit-feedback", "");
    const data = result.data; $("audit-rows").replaceChildren();
    $("audit-empty").hidden = true; $("audit-content").hidden = false;
    $("count-all").textContent = data.length;
    $("count-allow").textContent = data.filter(e => e.result === "allow").length;
    $("count-deny").textContent = data.filter(e => e.result === "deny").length;
    $("count-suspicious").textContent = data.filter(e => e.suspicious).length;
    for (const event of data) {
      const row = element("tr"); row.classList.toggle("is-suspicious", event.suspicious);
      row.classList.toggle("is-latest", latestRequests.has(event.request_id));
      const time = element("td"); time.append(element("strong", `#${event.id}`), element("small", new Date(event.timestamp).toLocaleTimeString("ru-RU", {timeZone:"Asia/Qyzylorda"})));
      const user = element("td"); user.append(element("strong", event.username), element("small", roleNames[event.role] || "Не авторизован"));
      const action = element("td"); action.append(element("strong", event.action), element("small", event.resource));
      const decision = element("td"); decision.append(element("span", `${event.result.toUpperCase()} · ${event.status_code}`, `badge ${event.result}`));
      const reason = element("td", event.reason);
      if (event.suspicious) reason.append(element("small", `Подозрительно: ${event.anomaly_reasons}`, "suspicious-text"));
      row.append(time, user, action, decision, reason); $("audit-rows").append(row);
    }
    $("audit-updated").textContent = `Обновлено ${new Date().toLocaleTimeString("ru-RU")} · время событий: Asia/Qyzylorda`;
  } catch (error) { feedback("audit-feedback", `Нет связи с сервером: ${error.message}`); }
  finally { pollBusy = false; }
}
function attackMessage(title, message, style = "") {
  const box = $("attack-result"); box.className = `attack-result ${style}`;
  box.replaceChildren(element("strong", title), element("p", message));
}
async function attack(kind) {
  if (attackBusy || Date.now() < cooldownUntil) return;
  attackBusy = true; updateAttackButtons();
  attackMessage("Выполняется проверка…", "Результат поступит от сервера.");
  try {
    const responses = [];
    if (kind === "missing") responses.push(await request("/api/me", {token: null}));
    else {
      const actor = await login("doctor_aidar"); let token = actor.access_token;
      if (kind === "tampered") {
        const parts = token.split("."); parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1); token = parts.join(".");
      }
      const count = kind === "spam" ? 15 : kind === "foreign" ? 3 : 1;
      for (let i = 0; i < count; i++) {
        responses.push(await request(kind === "foreign" ? "/api/patients/3" : "/api/me", {token, night:kind === "night"}));
      }
    }
    latestRequests = new Set(responses.map(r => r.requestId));
    const codes = [...new Set(responses.map(r => r.status))].map(code => `${responses.filter(r => r.status === code).length} × ${code}`).join(" / ");
    const entries = responses.map(r => `#${r.audit}`).join(", ");
    const anomaly = responses.some(r => r.suspicious);
    const last = responses.at(-1);
    const reason = last.data.detail || (kind === "night" ? "Ночной доступ отмечен как подозрительный." : "Проверка завершена.");
    attackMessage(`${codes}${anomaly ? " · Подозрительно" : ""}`, `${reason} Записи аудита: ${entries}. ${observer ? "Связанные строки отмечены синей линией в журнале." : "Подключите admin для просмотра журнала."}`, anomaly ? "is-suspicious" : "is-deny");
    // Fresh tokens do not bypass the per-user limiter. Give its window time to expire.
    if (kind === "spam" || last.status === 429) cooldownUntil = Date.now() + 10500;
    await pollAudit();
  } catch (error) { attackMessage("Проверка не завершена", `Ошибка соединения: ${error.message}`, "is-deny"); }
  finally { attackBusy = false; updateAttackButtons(); }
}
function updateAttackButtons() {
  const seconds = Math.max(0, Math.ceil((cooldownUntil - Date.now()) / 1000));
  attackButtons.forEach(button => {button.disabled = attackBusy || seconds > 0; button.title = seconds ? `Лимит восстановится через ${seconds} с` : "";});
  const existing = $("attack-cooldown");
  if (seconds) {
    const node = existing || element("p"); node.id = "attack-cooldown";
    node.textContent = `Следующая проверка через ${seconds} с — окно ограничения частоты.`;
    if (!existing) $("attack-result").append(node);
  } else existing?.remove();
}
userButtons.forEach(b => b.addEventListener("click", () => chooseUser(b.dataset.user)));
attackButtons.forEach(b => b.addEventListener("click", () => attack(b.dataset.attack)));
$("logout").addEventListener("click", () => {++loginVersion; current = null; setIdentity(); clearPatients(); feedback("login-feedback", "");});
$("refresh-patients").addEventListener("click", loadPatients);
$("manual-card").addEventListener("submit", event => {event.preventDefault(); openCard(Number($("patient-id").value));});
$("connect-audit").addEventListener("click", toggleObserver);
$("pause-audit").addEventListener("click", () => {paused = !paused; setObserver(); if (!paused) pollAudit();});
$("reset-demo").addEventListener("click", async () => {
  if (!observer || !confirm("Сбросить вымышленные карты и журнал? Все активные токены будут отозваны.")) return;
  const oldPause = paused; paused = true; $("reset-demo").disabled = true;
  try {
    const result = await request("/api/demo/reset", {token:observer.access_token, method:"POST"});
    if (!result.ok) { feedback("audit-feedback", describe(result)); return; }
    ++loginVersion; current = null; observer = null; latestRequests.clear(); cooldownUntil = 0;
    setIdentity(); clearPatients(); clearAudit(); setObserver(); updateAttackButtons();
    attackMessage("Демо восстановлено", "Выберите роль и подключите наблюдателя заново.");
    feedback("audit-feedback", "Данные восстановлены; журнал очищен и содержит событие сброса. Прежние токены отозваны.", true);
  } catch (error) { feedback("audit-feedback", `Сброс не выполнен: ${error.message}`); }
  finally {paused = oldPause; setObserver();}
});
setInterval(() => {if (!document.hidden) pollAudit();}, 2000);
setInterval(updateAttackButtons, 500);
setIdentity(); setObserver();
