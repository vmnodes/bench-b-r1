// store.js: where the expense claims are kept.
//
//   DATABASE_URL set   claims are kept in Postgres, across restarts and updates.
//   not set            claims are kept in memory and cleared on every restart.
//
// On the platform, DATABASE_URL is set for you when vmnodes.json says
// "database": true. There is no fallback: if DATABASE_URL is set but the
// database cannot be reached, the app refuses to start rather than quietly
// keeping claims in memory.
//
// A claim's owner is kept as owner_id: the identity's `id`, which never changes
// for a person. Never key on email: an address can be reused or changed.

// The database's shape, as an ordered list. Rules for this list:
//   - Add to the END. Never edit or delete an entry that has shipped.
//   - Every entry must be safe to run again: it runs at EVERY start-up, on a database
//     that may already have it.
//   - Only add things (tables, columns with a default, indexes). Never drop or rename.
const MIGRATIONS = [
  `create table if not exists claims (
     seq bigserial primary key,
     id uuid not null unique,
     owner_id text not null,
     owner_name text not null,
     purpose text not null,
     amount_cents integer not null check (amount_cents > 0),
     spent_on date not null,
     created_at timestamptz not null,
     status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
     decided_by_id text,
     decided_by_name text,
     decided_at timestamptz,
     reason text not null default ''
   )`,
  `create index if not exists claims_owner_idx on claims (owner_id)`,
];

// Pending claims first (they are what an approver is here for), then newest first.
// Pure, exported and used by both stores so the order is tested in one place.
function byPendingThenNewest(a, b) {
  const pa = a.status === "pending" ? 0 : 1;
  const pb = b.status === "pending" ? 0 : 1;
  if (pa !== pb) return pa - pb;
  return b.seq - a.seq;
}

function memoryStore() {
  const rows = [];
  let seq = 0;
  return {
    kind: "memory",
    async init() {},
    // ownerId: only that person's claims; null: everyone's (for approvers).
    async list(ownerId) { return rows.filter((r) => ownerId === null || r.ownerId === ownerId).sort(byPendingThenNewest).map((r) => ({ ...r })); },
    async get(id) { const r = rows.find((x) => x.id === id); return r ? { ...r } : null; },
    async add(r) { rows.push({ ...r, seq: ++seq, status: "pending", decidedById: null, decidedByName: null, decidedAt: null, reason: "" }); },
    // Only a pending claim can be decided. Returns the claim, or null if it was not pending.
    async decide(id, { status, byId, byName, reason, at }) {
      const r = rows.find((x) => x.id === id && x.status === "pending");
      if (!r) return null;
      Object.assign(r, { status, decidedById: byId, decidedByName: byName, reason, decidedAt: at });
      return { ...r };
    },
    async close() {},
  };
}

function postgresStore(url, { attempts = 5, delayMs = 1000, log = console } = {}) {
  const postgres = require("postgres");
  const sql = postgres(url, { max: 3, onnotice: () => {} });
  const cols = sql`seq, id, owner_id, owner_name, purpose, amount_cents, to_char(spent_on, 'YYYY-MM-DD') as spent_on, created_at, status, decided_by_id, decided_by_name, decided_at, reason`;
  const toClaim = (r) => ({
    seq: Number(r.seq), id: r.id, ownerId: r.owner_id, ownerName: r.owner_name, purpose: r.purpose, amountCents: r.amount_cents,
    spentOn: r.spent_on, createdAt: r.created_at.toISOString(), status: r.status, decidedById: r.decided_by_id,
    decidedByName: r.decided_by_name, decidedAt: r.decided_at ? r.decided_at.toISOString() : null, reason: r.reason,
  });
  return {
    kind: "postgres",
    async init() {
      // First, wait until the database answers. Only a database that cannot be reached is retried.
      for (let i = 1; ; i++) {
        try {
          await sql`select 1`;
          break;
        } catch (err) {
          if (i >= attempts) throw new Error(`could not reach the database after ${attempts} tries: ${err.message}`);
          log.log(`database not reachable yet (try ${i} of ${attempts}): ${err.message}`);
          await new Promise((r) => setTimeout(r, delayMs));
        }
      }
      // Then bring the database's shape up to date. NOT retried: a failed change stops the app and says why.
      // One transaction, under a lock, so two containers starting together cannot run the list at once.
      await sql.begin(async (tx) => {
        await tx`select pg_advisory_xact_lock(727002)`;
        for (const statement of MIGRATIONS) await tx.unsafe(statement);
      });
    },
    async list(ownerId) {
      const rows = ownerId === null
        ? await sql`select ${cols} from claims order by (status = 'pending') desc, seq desc`
        : await sql`select ${cols} from claims where owner_id = ${ownerId} order by (status = 'pending') desc, seq desc`;
      return rows.map(toClaim);
    },
    async get(id) {
      const rows = await sql`select ${cols} from claims where id = ${id}`;
      return rows[0] ? toClaim(rows[0]) : null;
    },
    async add(r) {
      await sql`insert into claims (id, owner_id, owner_name, purpose, amount_cents, spent_on, created_at)
                values (${r.id}, ${r.ownerId}, ${r.ownerName}, ${r.purpose}, ${r.amountCents}, ${r.spentOn}, ${r.createdAt})`;
    },
    // The "where status = 'pending'" is what stops two approvers deciding the same claim.
    async decide(id, { status, byId, byName, reason, at }) {
      const rows = await sql`update claims set status = ${status}, decided_by_id = ${byId}, decided_by_name = ${byName}, reason = ${reason}, decided_at = ${at}
                             where id = ${id} and status = 'pending' returning ${cols}`;
      return rows[0] ? toClaim(rows[0]) : null;
    },
    async close() { await sql.end({ timeout: 5 }); },
  };
}

function openStore({ env = process.env, log = console } = {}) {
  return env.DATABASE_URL ? postgresStore(env.DATABASE_URL, { log }) : memoryStore();
}

module.exports = { openStore, byPendingThenNewest, MIGRATIONS };
