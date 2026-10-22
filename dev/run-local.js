// dev/run-local.js: `npm run dev`. Starts the app plus the pretend portal, then
// open http://127.0.0.1:4100 in your browser.
//   npm run dev              signed in as Sam Staff (a submitter)
//   npm run dev -- approver  signed in as Avery Approver
// While it is running, visit /_as/staff, /_as/colleague, /_as/approver, /_as/both or /_as/nobody to switch.
const { spawn } = require("node:child_process");
const path = require("node:path");
const { startMockPortal } = require("./mock-portal");

const PORTAL_PORT = 4100, APP_PORT = 3000, APP_ID = "app_local_dev";

(async () => {
  const portal = await startMockPortal({ port: PORTAL_PORT, appUrl: `http://127.0.0.1:${APP_PORT}`, appId: APP_ID, as: process.argv[2] || "staff" });
  const app = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    stdio: "inherit",
    env: { ...process.env, PORT: String(APP_PORT), VMNODES_PORTAL_URL: portal.issuer, VMNODES_APP_ID: APP_ID },
  });
  app.on("exit", (code) => { console.log(`app exited (${code})`); process.exit(code || 0); });
  console.log(`\n  Open ${portal.issuer} in your browser.\n`);
  const stop = () => { app.kill(); portal.server.close(); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
})().catch((e) => { console.error(e.message); process.exit(1); });
