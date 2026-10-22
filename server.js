// server.js: the whole app. Expense claims: staff claim back money they spent on work,
// and an approver approves or rejects each claim.
//
// Who may do what, and every one of these is checked on the SERVER, on every request:
//   expense-claims.submitter   raise a claim; see only their own claims
//   expense-claims.approver    see every claim; approve or reject one (never their own);
//                              can also raise claims of their own
//   neither                    nothing: the app answers 403
const http = require("node:http");
const crypto = require("node:crypto");
const { VmnodesIdentity, IdentityError } = require("@vmnodes/identity");
const { openStore } = require("./store");

const APP_NAME = process.env.VMNODES_APP_NAME || "expense-claims";
// Must match the role names in vmnodes.json exactly.
const ROLE_PREFIX = "expense-claims";
const SUBMITTER_ROLE = `${ROLE_PREFIX}.submitter`;
const APPROVER_ROLE = `${ROLE_PREFIX}.approver`;
const VERSION = require("./package.json").version;
// Set when the image is built (see Dockerfile). Reported as-is, never guessed.
const BUILD_COMMIT = process.env.BUILD_COMMIT || null;
const PORT = Number(process.env.PORT || 3000);
const LISTEN_ADDRESS = process.env.LISTEN_ADDRESS || undefined;

let identity;
try {
  identity = new VmnodesIdentity();
} catch (err) {
  console.error(`${err.message}\nThe platform sets these when your app is deployed; locally, \`npm run dev\` sets them for you.`);
  process.exit(1);
}
const store = openStore();

const KEPT = {
  postgres: "Claims are kept in this app's database, across restarts and updates.",
  memory: "Claims are kept in memory, so they are cleared when the app restarts or is updated.",
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const money = (cents) => (cents / 100).toFixed(2);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Locked down: no scripts at all, nobody can frame the page (so nobody can trick an approver
// into clicking a button under a decoy), and forms can only post back to this app.
const SECURITY_HEADERS = {
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};

function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "content-type": type, ...SECURITY_HEADERS });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

function redirect(res, location) {
  res.writeHead(303, { location, ...SECURITY_HEADERS });
  res.end();
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > limit) { reject(new IdentityError("body too large", 413)); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// Reads named text fields from a form post or a JSON post. Never trusts the types.
async function readFields(req, names) {
  const raw = await readBody(req);
  const json = (req.headers["content-type"] || "").includes("application/json");
  const o = json ? JSON.parse(raw || "{}") : Object.fromEntries(new URLSearchParams(raw));
  if (o === null || typeof o !== "object") throw new SyntaxError("body must be a JSON object");
  return Object.fromEntries(names.map((n) => [n, typeof o[n] === "string" || typeof o[n] === "number" ? String(o[n]).trim() : ""]));
}

// "12", "12.5" and "12.50" are fine; "-3", "1e3" and "12.345" are not. Returns whole cents, or null.
function parseAmount(text) {
  const m = /^(\d{1,7})(?:\.(\d{1,2}))?$/.exec(text);
  if (!m) return null;
  const cents = Number(m[1]) * 100 + Number((m[2] || "").padEnd(2, "0"));
  return cents > 0 ? cents : null;
}

// "YYYY-MM-DD" that is a real calendar day, from 2000 up to tomorrow (a day of slack for time zones).
// Returns the same text, or null. `now` is injectable so the rule can be tested.
function parseSpentOn(text, now = new Date()) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
  if (y < 2000) return null;
  const tomorrow = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return dt.getTime() > tomorrow ? null : text;
}

// Blocks a form or request sent from another website using the visitor's signed-in browser
// (cross-site request forgery). Browsers always say where a request came from in Sec-Fetch-Site
// and Origin, and a web page cannot change either. Requests with neither (command-line tools)
// carry no browser session to abuse.
function refuseCrossSite(req) {
  const site = req.headers["sec-fetch-site"];
  if (site !== undefined) {
    if (site === "same-origin" || site === "none") return;
    throw new IdentityError("cross-site request refused", 403);
  }
  const origin = req.headers["origin"];
  if (origin !== undefined) {
    let host = null;
    try { host = new URL(origin).host; } catch { /* host stays null */ }
    const own = [req.headers["x-forwarded-host"], req.headers["host"]].filter(Boolean).map((h) => String(h).split(",")[0].trim());
    if (host === null || !own.includes(host)) throw new IdentityError("cross-site request refused", 403);
  }
}

const holds = (user, role) => user.roles.includes(role);

function view(r) {
  return { id: r.id, ownerName: r.ownerName, purpose: r.purpose, amount: money(r.amountCents), spentOn: r.spentOn, createdAt: r.createdAt, status: r.status, decidedByName: r.decidedByName, decidedAt: r.decidedAt, reason: r.reason };
}

function shell(inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Expense claims</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#0b0c10;color:#e8e8ee;max-width:900px;margin:0 auto;padding:16px}table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #2a2c35;padding:8px 6px;vertical-align:top}small,th{color:#a8aab8;font-weight:normal}label{display:block;margin-top:8px}input{width:100%;background:#15161c;color:inherit;border:1px solid #2a2c35;border-radius:6px;padding:8px;box-sizing:border-box;font:inherit}button{margin:8px 8px 0 0;background:#5b5bd6;color:#fff;border:0;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer}button.reject{background:#8a2f2f}.err{border:1px solid #d65b5b;border-radius:6px;padding:8px}code{font-family:ui-monospace,monospace}.st{font-weight:600}.st-approved{color:#6fd08c}.st-rejected{color:#ff8a8a}.st-pending{color:#f0c36a}.amt{white-space:nowrap;text-align:right}</style></head><body>${inner}</body></html>`;
}

const STATUS_LABEL = { pending: "Waiting for approval", approved: "Approved", rejected: "Rejected" };

function page(user, claims, { error = "", values = {}, today = new Date() } = {}) {
  const approver = holds(user, APPROVER_ROLE);
  const rows = claims.length
    ? claims.map((r) => {
      // Showing the buttons only to approvers is a courtesy. The server checks the role again on every decision.
      const decide = r.status === "pending" && approver && r.ownerId !== user.id
        ? `<form method="post" action="/claims/${esc(r.id)}/decision"><input name="reason" maxlength="300" placeholder="Reason (optional, shown to the claimant)" aria-label="Reason for ${esc(r.purpose)}"><button name="decision" value="approve" type="submit">Approve</button><button class="reject" name="decision" value="reject" type="submit">Reject</button></form>`
        : "";
      const by = r.status === "pending" ? "" : ` by ${esc(r.decidedByName)}`;
      const why = r.reason ? `<br><small>Reason: ${esc(r.reason)}</small>` : "";
      const status = `<span class="st st-${esc(r.status)}">${esc(STATUS_LABEL[r.status])}</span>${by}${why}`;
      const who = approver ? `<td>${esc(r.ownerName)}</td>` : "";
      return `<tr><td>${esc(r.spentOn)}</td>${who}<td>${esc(r.purpose)}</td><td class="amt">${esc(money(r.amountCents))}</td><td>${status}${decide}</td></tr>`;
    }).join("")
    : `<tr><td colspan="${approver ? 5 : 4}">No claims yet.</td></tr>`;
  const maxDate = new Date(today.getTime() + 24 * 3600 * 1000).toISOString().slice(0, 10);
  const form = `<h2>New claim</h2><form method="post" action="/claims">${error ? `<p class="err" role="alert">${esc(error)}</p>` : ""}
<label for="purpose">What was it for?</label><input id="purpose" name="purpose" required maxlength="200" value="${esc(values.purpose || "")}">
<label for="amount">How much?</label><input id="amount" name="amount" required inputmode="decimal" placeholder="49.90" value="${esc(values.amount || "")}">
<label for="spentOn">Date you spent it</label><input id="spentOn" name="spentOn" type="date" required min="2000-01-01" max="${maxDate}" value="${esc(values.spentOn || "")}">
<button type="submit">Submit claim</button></form>`;
  return shell(`<h1>Expense claims</h1><p id="who">Signed in as <strong>${esc(user.name || user.email)}</strong>${approver ? " (approver)" : ""}</p>${form}
<h2>${approver ? "All claims" : "Your claims"}</h2><table><thead><tr><th>Date</th>${approver ? "<th>Claimed by</th>" : ""}<th>What it was for</th><th class="amt">Amount</th><th>Status</th></tr></thead><tbody id="claims">${rows}</tbody></table>
<p><small>${esc(KEPT[store.kind])}</small></p>`);
}

async function handle(req, res) {
  const url = new URL(req.url, "http://app");
  const isApi = url.pathname.startsWith("/api/");

  // Health is checked by the platform directly, with no signed-in person, so it must NOT require sign-in.
  if (url.pathname === "/health") {
    return send(res, 200, { status: "ok", app: APP_NAME, version: VERSION, buildCommit: BUILD_COMMIT, storage: store.kind });
  }

  const user = await identity.currentUser(req.headers);
  // Holding neither role means no business here at all.
  if (!holds(user, SUBMITTER_ROLE) && !holds(user, APPROVER_ROLE)) {
    throw new IdentityError(`role '${SUBMITTER_ROLE}' or '${APPROVER_ROLE}' required`, 403);
  }
  // Approvers see everything; everyone else sees only what they raised. The key is user.id, never the email.
  const scope = () => (holds(user, APPROVER_ROLE) ? null : user.id);

  if (url.pathname === "/" && req.method === "GET") return send(res, 200, page(user, await store.list(scope())), "text/html; charset=utf-8");
  if (url.pathname === "/api/me" && req.method === "GET") return send(res, 200, { id: user.id, name: user.name, roles: user.roles });
  if (url.pathname === "/api/claims" && req.method === "GET") return send(res, 200, { items: (await store.list(scope())).map(view) });

  const one = url.pathname.match(/^\/api\/claims\/([^/]+)$/);
  if (one && req.method === "GET") {
    const r = UUID.test(one[1]) ? await store.get(one[1].toLowerCase()) : null;
    // Someone else's claim and a claim that does not exist get the SAME answer, so nobody can probe for ids.
    if (!r || (scope() !== null && r.ownerId !== user.id)) return send(res, 404, { error: "no such claim" });
    return send(res, 200, view(r));
  }

  if ((url.pathname === "/claims" || url.pathname === "/api/claims") && req.method === "POST") {
    refuseCrossSite(req);
    const f = await readFields(req, ["purpose", "amount", "spentOn"]);
    const amountCents = parseAmount(f.amount);
    const spentOn = parseSpentOn(f.spentOn);
    const problem = !f.purpose ? "say what it was for" : f.purpose.length > 200 ? "what it was for must be at most 200 characters"
      : amountCents === null ? "amount must be a positive number with at most two decimals, for example 49.90"
        : spentOn === null ? "date must be a real date, written YYYY-MM-DD, not in the future" : null;
    if (problem) {
      if (isApi) return send(res, 400, { error: problem });
      return send(res, 400, page(user, await store.list(scope()), { error: problem, values: f }), "text/html; charset=utf-8");
    }
    const r = { id: crypto.randomUUID(), ownerId: user.id, ownerName: user.name || user.email, purpose: f.purpose, amountCents, spentOn, createdAt: new Date().toISOString() };
    await store.add(r);
    if (!isApi) return redirect(res, "/");
    return send(res, 201, view({ ...r, status: "pending", decidedByName: null, decidedAt: null, reason: "" }));
  }

  const decision = url.pathname.match(/^\/(?:api\/)?claims\/([^/]+)\/decision$/);
  if (decision && req.method === "POST") {
    refuseCrossSite(req);
    identity.requireRole(user, APPROVER_ROLE); // checked on the SERVER, whatever the page showed
    const f = await readFields(req, ["decision", "reason"]);
    if (f.decision !== "approve" && f.decision !== "reject") return send(res, 400, { error: "decision must be approve or reject" });
    if (f.reason.length > 300) return send(res, 400, { error: "reason must be at most 300 characters" });
    const r = UUID.test(decision[1]) ? await store.get(decision[1].toLowerCase()) : null;
    if (!r) return send(res, 404, { error: "no such claim" });
    if (r.ownerId === user.id) return send(res, 403, { error: "you cannot decide your own claim" });
    const status = f.decision === "approve" ? "approved" : "rejected";
    const decided = await store.decide(r.id, { status, byId: user.id, byName: user.name || user.email, reason: f.reason, at: new Date().toISOString() });
    if (!decided) return send(res, 409, { error: "this claim has already been decided" });
    console.log(`claim ${decided.id} ${status} by ${user.id}`);
    if (!isApi) return redirect(res, "/");
    return send(res, 200, view(decided));
  }

  return send(res, 404, { error: "not found" });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    const status = err instanceof IdentityError ? err.status : err instanceof SyntaxError ? 400 : 500;
    if (status >= 500) console.error(err.cause || err);
    const message = status === 500 ? "something went wrong" : err.message;
    if (new URL(req.url, "http://app").pathname.startsWith("/api/")) return send(res, status, { error: message });
    send(res, status, shell(`<h1>Expense claims</h1><p>${esc(message)}</p>${status === 403 ? "<p>Ask whoever runs this app to give you a role.</p>" : ""}`), "text/html; charset=utf-8");
  });
});
store.init().then(
  () => server.listen({ port: PORT, host: LISTEN_ADDRESS }, () => console.log(`${APP_NAME} ${VERSION} listening on :${server.address().port} (claims kept in ${store.kind})`)),
  (err) => {
    console.error(`${err.message}\nDATABASE_URL is set, so this app will not start without its database.`);
    process.exit(1);
  },
);
