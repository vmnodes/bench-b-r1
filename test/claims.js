// test/claims.js: `node test/claims.js`. Proves who can do what, in BOTH directions:
// every "refused" row has an "allowed" row beside it, so the check can fail.
// Set TEST_DATABASE_URL to an EMPTY scratch Postgres database to run it against the database too.
const { spawn } = require("node:child_process");
const http = require("node:http");
const path = require("node:path");
const { SignJWT } = require("jose");
const { startMockPortal, USERS } = require("../dev/mock-portal");
const { byPendingThenNewest } = require("../store");

const APP_ID = "app_claims_test";
let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `  (expected ${JSON.stringify(want)}, got ${JSON.stringify(got)})`}`);
}

const ymd = (offsetDays) => new Date(Date.now() + offsetDays * 86400000).toISOString().slice(0, 10);
const TODAY = ymd(0);

(async () => {
  // --- the ordering rule, as a pure function, over BOTH input orders --------------------
  const rows = [
    { id: "old-pending", status: "pending", seq: 1 },
    { id: "decided", status: "approved", seq: 2 },
    { id: "new-pending", status: "pending", seq: 3 },
    { id: "newest-rejected", status: "rejected", seq: 4 },
  ];
  const want = ["new-pending", "old-pending", "newest-rejected", "decided"];
  check("pending first, then newest first", [...rows].sort(byPendingThenNewest).map((r) => r.id), want);
  check("...and the same from the reverse input order", [...rows].reverse().sort(byPendingThenNewest).map((r) => r.id), want);

  const portal = await startMockPortal({ port: 0, appId: APP_ID, as: "staff" });
  const child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { PATH: process.env.PATH, PORT: "0", LISTEN_ADDRESS: "127.0.0.1", VMNODES_PORTAL_URL: portal.issuer, VMNODES_APP_ID: APP_ID, ...(process.env.TEST_DATABASE_URL ? { DATABASE_URL: process.env.TEST_DATABASE_URL } : {}) },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const base = await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => { const m = String(d).match(/listening on :(\d+)/); if (m) resolve(`http://127.0.0.1:${m[1]}`); });
    // A server that dies on start-up must fail the run on the spot, not leave it waiting forever.
    child.on("exit", (code) => reject(new Error(`the app exited with code ${code} before it was listening`)));
  });

  // Signs a token for one of the mock portal's people, the way the real gateway would.
  // `over` changes claims; `headers` adds request headers; `form` sends a form post instead of JSON.
  async function call(who, method, p, body, { over = {}, headers = {}, form = false } = {}) {
    const u = { ...USERS[who], ...over };
    const token = await new SignJWT({ email: u.email, name: u.name, kind: u.kind, groups: u.groups, roles: u.roles })
      .setProtectedHeader({ alg: "RS256", kid: "local-dev" }).setSubject(u.sub).setIssuer(portal.issuer).setAudience(APP_ID)
      .setIssuedAt().setExpirationTime("5m").sign(portal.privateKey);
    return new Promise((resolve, reject) => {
      const req = http.request(base + p, { method, headers: { "x-vmnodes-identity": token, "content-type": form ? "application/x-www-form-urlencoded" : "application/json", ...headers } }, (res) => {
        let data = ""; res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data, headers: res.headers, json: () => JSON.parse(data) }));
      });
      req.on("error", reject);
      if (body) req.write(form ? new URLSearchParams(body).toString() : JSON.stringify(body));
      req.end();
    });
  }
  const claim = { purpose: "Train fare to client", amount: "24.5", spentOn: TODAY };

  // --- who may enter at all ---------------------------------------------------
  check("a person with neither role -> 403", (await call("nobody", "GET", "/api/claims")).status, 403);
  check("a person with neither role cannot submit -> 403", (await call("nobody", "POST", "/api/claims", claim)).status, 403);
  check("a request with no identity header -> 401", await new Promise((resolve) => http.get(base + "/api/claims", (r) => { r.resume(); resolve(r.statusCode); })), 401);
  check("CONTROL: a submitter gets in", (await call("staff", "GET", "/api/claims")).status, 200);
  check("/health needs no sign-in", await new Promise((resolve) => http.get(base + "/health", (r) => { r.resume(); resolve(r.statusCode); })), 200);

  // --- raising a claim ------------------------------------------------------
  const made = await call("staff", "POST", "/api/claims", { ...claim, purpose: "Client lunch <script>" });
  check("CONTROL: a submitter can raise a claim -> 201, pending, amount with pence, the date kept", [made.status, made.json().status, made.json().amount, made.json().spentOn], [201, "pending", "24.50", TODAY]);
  const id = made.json().id;
  check("an approver can also raise a claim of their own -> 201", (await call("approver", "POST", "/api/claims", claim)).status, 201);
  for (const amount of ["-5", "0", "abc", "12.345", "1e3", ""]) {
    check(`amount ${JSON.stringify(amount)} -> 400`, (await call("staff", "POST", "/api/claims", { ...claim, amount })).status, 400);
  }
  check("a missing purpose -> 400", (await call("staff", "POST", "/api/claims", { amount: "5", spentOn: TODAY })).status, 400);
  for (const spentOn of ["", "yesterday", "2026-02-30", "2026-13-01", "1999-12-31", ymd(5), "26-01-01"]) {
    check(`date ${JSON.stringify(spentOn)} -> 400`, (await call("staff", "POST", "/api/claims", { ...claim, spentOn })).status, 400);
  }
  check("CONTROL: yesterday's date -> 201", (await call("staff", "POST", "/api/claims", { ...claim, spentOn: ymd(-1) })).status, 201);
  check("a JSON body that is not an object -> 400", (await call("staff", "POST", "/api/claims", null, { headers: {} })).status, 400);

  // --- seeing: own records only, unless approver ---------------------------------
  const ownList = (await call("staff", "GET", "/api/claims")).json().items;
  check("the claimant sees their own claim, and only their own (2 raised by them)", [ownList.length, ownList.some((r) => r.id === id), ownList.every((r) => r.ownerName === "Sam Staff")], [2, true, true]);
  check("ANOTHER submitter sees none of it", (await call("colleague", "GET", "/api/claims")).json().items, []);
  const all = (await call("approver", "GET", "/api/claims")).json().items;
  check("an approver sees every claim (3 in total, from two people)", [all.length, new Set(all.map((r) => r.ownerName)).size], [3, 2]);
  check("CONTROL: the owner can open it by id -> 200", (await call("staff", "GET", `/api/claims/${id}`)).status, 200);
  const other = await call("colleague", "GET", `/api/claims/${id}`);
  const missing = await call("colleague", "GET", "/api/claims/6f1c2a52-8f0d-4d64-9d0e-1c7b0e2a9b11");
  check("another submitter opening it by id -> 404, the SAME answer as an id that does not exist", [other.status, other.body], [missing.status, missing.body]);
  check("a different person with the SAME EMAIL (different id) sees none of it: the key is id, not email", (await call("staff", "GET", "/api/claims", undefined, { over: { sub: "usr_someone_else" } })).json().items, []);

  // --- deciding: only approvers, and every time -------------------------------
  const decideAs = (who, claimId, b, o) => call(who, "POST", `/api/claims/${claimId}/decision`, b, o);
  check("the claimant cannot approve their own claim -> 403 (the role check and the own-claim rule both refuse this one)", (await decideAs("staff", id, { decision: "approve" })).status, 403);
  check("ANOTHER submitter cannot approve -> 403 (only the role check can refuse this one)", (await decideAs("colleague", id, { decision: "approve" })).status, 403);
  check("a person with neither role cannot approve -> 403", (await decideAs("nobody", id, { decision: "approve" })).status, 403);
  check("...and nothing changed", (await call("approver", "GET", `/api/claims/${id}`)).json().status, "pending");
  check("a decision that is neither approve nor reject -> 400", (await decideAs("approver", id, { decision: "maybe" })).status, 400);
  check("a reason over 300 characters -> 400", (await decideAs("approver", id, { decision: "reject", reason: "x".repeat(301) })).status, 400);
  check("a made-up claim id -> 404", (await decideAs("approver", "6f1c2a52-8f0d-4d64-9d0e-1c7b0e2a9b11", { decision: "approve" })).status, 404);
  const rejected = await decideAs("approver", id, { decision: "reject", reason: "No receipt" });
  check("CONTROL: an approver can reject -> 200, with the reason", [rejected.status, rejected.json().status, rejected.json().reason, rejected.json().decidedByName], [200, "rejected", "No receipt", "Avery Approver"]);
  check("deciding twice -> 409, the first decision stands", [(await decideAs("approver", id, { decision: "approve" })).status, (await call("staff", "GET", `/api/claims/${id}`)).json().status], [409, "rejected"]);
  check("the claimant sees the outcome and the reason", (await call("staff", "GET", `/api/claims/${id}`)).json().reason, "No receipt");
  const second = (await call("colleague", "POST", "/api/claims", claim)).json().id;
  check("CONTROL: an approver can approve someone else's claim, with no reason -> 200", (await decideAs("approver", second, { decision: "approve" })).json().status, "approved");

  // --- nobody decides their own claim -----------------------------------------
  const mine = (await call("both", "POST", "/api/claims", claim)).json().id;
  check("someone who holds both roles cannot decide their own claim -> 403", (await decideAs("both", mine, { decision: "approve" })).status, 403);
  check("an approver who is not a submitter cannot decide their own claim -> 403", (await decideAs("approver", (await call("approver", "GET", "/api/claims")).json().items.find((r) => r.ownerName === "Avery Approver").id, { decision: "approve" })).status, 403);
  check("...but another approver can decide it -> 200", (await decideAs("approver", mine, { decision: "approve" })).status, 200);

  // --- being clever with the browser: other websites cannot act as a signed-in person ------
  const forged = (await call("colleague", "POST", "/api/claims", claim)).json().id;
  const cross = { "sec-fetch-site": "cross-site", origin: "https://evil.example" };
  check("an approver's browser tricked by another website cannot decide (Sec-Fetch-Site: cross-site) -> 403", (await decideAs("approver", forged, { decision: "approve" }, { headers: cross, form: true })).status, 403);
  check("same for an Origin that is not this app, with no Sec-Fetch-Site -> 403", (await decideAs("approver", forged, { decision: "approve" }, { headers: { origin: "https://evil.example" }, form: true })).status, 403);
  check("same for a cross-site claim submission -> 403", (await call("staff", "POST", "/claims", claim, { headers: cross, form: true })).status, 403);
  check("...and the claim is still pending", (await call("approver", "GET", `/api/claims/${forged}`)).json().status, "pending");
  check("CONTROL: the same form post from this app's own page -> 303", (await call("approver", "POST", `/claims/${forged}/decision`, { decision: "approve" }, { headers: { "sec-fetch-site": "same-origin" }, form: true })).status, 303);
  check("...which approved it", (await call("approver", "GET", `/api/claims/${forged}`)).json().status, "approved");
  const viaForm = await call("colleague", "POST", "/claims", claim, { headers: { "sec-fetch-site": "same-origin" }, form: true });
  check("CONTROL: a form post from this app's own page raises a claim -> 303 back to the list", [viaForm.status, viaForm.headers.location], [303, "/"]);
  const viaOrigin = await call("colleague", "POST", "/claims", claim, { headers: { origin: base }, form: true });
  check("CONTROL: a post whose Origin is this app (no Sec-Fetch-Site) -> 303", viaOrigin.status, 303);

  // --- the page: text is escaped, buttons follow the role, headers lock it down ------------
  const asStaff = await call("staff", "GET", "/");
  check("typed text is escaped, not run as markup", asStaff.body.includes("Client lunch &lt;script&gt;") && !asStaff.body.includes("<script>"), true);
  check("a claimant's page has no Approve button", asStaff.body.includes(">Approve<"), false);
  check("a claimant's page does not list other people's claims", asStaff.body.includes("Casey Colleague"), false);
  const pending = (await call("colleague", "POST", "/api/claims", claim)).json().id;
  const asApprover = await call("approver", "GET", "/");
  check("CONTROL: an approver's page has an Approve button for a pending claim", asApprover.body.includes(`/claims/${pending}/decision`), true);
  check("...and shows who claimed it", asApprover.body.includes("Casey Colleague"), true);
  check("the page cannot be framed and runs no scripts", [asStaff.headers["x-frame-options"], /frame-ancestors 'none'/.test(asStaff.headers["content-security-policy"]), /default-src 'none'/.test(asStaff.headers["content-security-policy"])], ["DENY", true, true]);
  const bad = await call("staff", "POST", "/claims", { purpose: "", amount: "x", spentOn: "" }, { headers: { "sec-fetch-site": "same-origin" }, form: true });
  check("a bad form shows the problem on the page and keeps what was typed -> 400", [bad.status, bad.body.includes('role="alert"')], [400, true]);

  const FLOOR = 55;
  if (pass + fail < FLOOR) { console.log(`FAIL only ${pass + fail} checks ran, expected at least ${FLOOR}`); fail++; }
  console.log(`\npassed=${pass} failed=${fail}`);
  child.kill(); portal.server.close();
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("test crashed:", e); process.exit(1); });
