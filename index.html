// Orange Track match database v3.0 (Cloudflare Worker + D1, or self-hosted with server.mjs) by 0rangess_
// v3: Valve match IDs, ranked flag, hero IDs, mod version + game language per upload, data source priority
//     (post-game page > end of match > saved snapshot), and result-less uploads from old versions are refused.
// Stores match stats uploaded by Orange Track users, so matches the Deadlock API
// hasn't recorded can still be counted. Needs a D1 binding called DB.
// Optional secret ADMIN_KEY enables deleting a player's data on request.
// Optional secret KOFI_TOKEN (the verification token from Ko-fi > Settings > API) turns on the
// Ko-fi webhook at /kofi, which keeps the supporters list Orange Track shows (v2.4).
//
// v2 is built to stay inside Cloudflare's free daily limits (rows read / rows written):
//  - a match is found by a fingerprint of its players (1 indexed lookup, not a scan of every recent match)
//  - player rows carry the match start, so "this player's recent matches" reads only the rows it returns
//  - repeat uploads only write rows whose stats actually changed; no per-upload rate-limit rows
//  - the health check doesn't count the whole table

const ALLOWED_ORIGINS = ["https://0r8nge.github.io"];
const MAX_PER_HOUR = 40;            // uploads per IP per hour (kept in memory, not in the database)
// Matches are kept for as long as there's room. Cloudflare's free plan allows 500 MB per database
// (5 GB is the total across all your databases), so once this one passes MAX_DB_MB the oldest
// matches are deleted first. On the paid plan (10 GB per database) raise MAX_DB_MB to about 9500.
const MAX_DB_MB = 450;
const TRIM_MATCHES = 2000;          // how many of the oldest matches go each time it's over
const MODES = ["normal", "street_brawl", "unknown"];
// where an upload's stats came from, best last: a higher source overwrites a lower one, never the other way round
const SOURCES = { legacy: 1, saved: 1, end: 2, postgame: 3 };
const VERSION = 3;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS matches (key TEXT PRIMARY KEY, start INTEGER NOT NULL, dur INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL DEFAULT 'unknown',
     votes0 INTEGER NOT NULL DEFAULT 0, votes1 INTEGER NOT NULL DEFAULT 0, uploaders INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS players (key TEXT NOT NULL, acc INTEGER NOT NULL, name TEXT, hero TEXT, team INTEGER NOT NULL,
     k INTEGER, d INTEGER, a INTEGER, souls INTEGER, obj INTEGER, lvl INTEGER, PRIMARY KEY (key, acc))`,
  `CREATE TABLE IF NOT EXISTS uploads (key TEXT NOT NULL, uploader TEXT NOT NULL, result INTEGER, PRIMARY KEY (key, uploader))`,
  `CREATE INDEX IF NOT EXISTS matches_start ON matches(start)`,
  // Ko-fi supporters: only what's needed to say thank you. name is NULL when the supporter chose to stay private.
  `CREATE TABLE IF NOT EXISTS supporters (tx TEXT PRIMARY KEY, name TEXT, monthly INTEGER NOT NULL, t INTEGER NOT NULL)`,
];
// one-time upgrade from v1 (adds the fingerprint + start columns and better indexes, drops what isn't needed)
const MIGRATE_V2 = [
  `ALTER TABLE matches ADD COLUMN fp TEXT`,
  `ALTER TABLE players ADD COLUMN start INTEGER`,
  `UPDATE players SET start = (SELECT start FROM matches WHERE matches.key = players.key) WHERE start IS NULL`,
  `CREATE INDEX IF NOT EXISTS matches_fp ON matches(fp)`,
  `CREATE INDEX IF NOT EXISTS players_acc_start ON players(acc, start)`,
  `DROP INDEX IF EXISTS players_acc`,
  `DROP TABLE IF EXISTS rate`,
];
// v3 columns (added one by one, only if missing, so a half-finished upgrade fixes itself)
const V3_COLS = {
  matches: [["mid", "INTEGER"], ["ranked", "INTEGER"], ["src", "INTEGER NOT NULL DEFAULT 0"]],
  players: [["hid", "INTEGER"], ["dmg", "INTEGER"], ["heal", "INTEGER"]],
  uploads: [["ver", "TEXT"], ["lang", "TEXT"], ["src", "INTEGER"], ["left_early", "INTEGER"], ["t", "INTEGER"]],
};
const V3_INDEX = [
  `CREATE UNIQUE INDEX IF NOT EXISTS matches_mid ON matches(mid) WHERE mid IS NOT NULL`,
];
let ready = false;
// checks the real columns (not just a version number), so a half-finished upgrade fixes itself
async function cols(env, table) {
  try { const r = await env.DB.prepare(`SELECT name FROM pragma_table_info('${table}')`).all(); return (r.results || []).map(x => x.name); }
  catch (e) { return null; }
}
async function init(env) {
  if (ready) return;
  for (const s of SCHEMA) await env.DB.prepare(s).run();
  const m = await cols(env, "matches"), p = await cols(env, "players");
  if (!m || !p || !m.includes("fp") || !p.includes("start")) {
    if (m && !m.includes("fp")) await env.DB.prepare("ALTER TABLE matches ADD COLUMN fp TEXT").run();
    if (p && !p.includes("start")) await env.DB.prepare("ALTER TABLE players ADD COLUMN start INTEGER").run();
    for (const s of MIGRATE_V2.slice(2)) await env.DB.prepare(s).run();
  }
  for (const table of Object.keys(V3_COLS)) {
    const have = await cols(env, table);
    if (!have) continue;
    for (const [name, type] of V3_COLS[table]) if (!have.includes(name)) await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`).run();
  }
  for (const s of V3_INDEX) await env.DB.prepare(s).run();
  await env.DB.prepare("INSERT INTO meta (k, v) VALUES ('version', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(VERSION).run();
  ready = true;
}

function cors(req) {
  const o = req.headers.get("Origin") || "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
    "Vary": "Origin",
  };
}
function json(req, body, status = 200, extra) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors(req), ...(extra || {}) } });
}
const now = () => Math.floor(Date.now() / 1000);
const int = (v, lo, hi) => { v = Math.round(Number(v)); return Number.isFinite(v) && v >= lo && v <= hi ? v : null; };
const str = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, max) : "");
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("").slice(0, 20);
}

// ---------- rate limit (per worker instance, in memory) ----------
const hits = new Map();
function limited(ip) {
  const h = Math.floor(now() / 3600), k = ip + ":" + h, n = (hits.get(k) || 0) + 1;
  hits.set(k, n);
  if (hits.size > 5000) for (const key of hits.keys()) if (!key.endsWith(":" + h)) hits.delete(key);
  return n > MAX_PER_HOUR;
}

// ---------- validation ----------
function clean(body) {
  if (!body || typeof body !== "object") return "bad body";
  const t = now();
  const m = {
    uploader: int(body.uploader, 0, 4294967295) || 0,
    start: int(body.start, t - (Number(body.v) >= 2 ? 3 * 86400 : 6 * 3600), t + 600),   // 4.2 may send a saved match up to 3 days later
    dur: int(body.dur, 0, 7200),
    mode: MODES.includes(body.mode) ? body.mode : "unknown",
    result: body.result === "win" ? 1 : body.result === "loss" ? 0 : null,
    players: [],
    // v3 (Orange Track 4.2+)
    v: int(body.v, 1, 99) || 1,
    mid: /^\d{1,15}$/.test(String(body.mid || "")) ? Number(body.mid) : null,      // Valve's match ID
    ranked: body.ranked === true ? 1 : body.ranked === false ? 0 : null,
    ver: str(body.ver, 12) || null,
    lang: str(body.lang, 16).toLowerCase() || null,
    src: SOURCES[body.src] || (body.v >= 2 ? SOURCES.end : SOURCES.legacy),
    left: body.left === true ? 1 : 0,
    abs: body.abs === true,                                                        // teams are Team 1 / Team 2, not "mine / theirs"
  };
  // old versions (before 4.2) upload unfinished matches without a result: refuse those, with a message they show
  if (m.v < 2 && m.result === null) return "please update Orange Track";
  if (m.start === null) return "bad start time";
  if (m.dur === null) return "bad duration";
  if (!Array.isArray(body.players) || body.players.length < 2 || body.players.length > 12) return "bad player list";
  const seen = new Set();
  for (const p of body.players) {
    const acc = int(p && p.acc, 1, 4294967295);
    if (!acc || seen.has(acc)) continue;          // bots / unknown players are skipped
    seen.add(acc);
    const q = { acc, name: str(p.name, 64), hero: str(p.hero, 32), hid: int(p.hid, 1, 999), dmg: int(p.dmg, 0, 2000000), heal: int(p.heal, 0, 2000000), team: p.team === 1 ? 1 : 0,
                k: int(p.k, 0, 150), d: int(p.d, 0, 150), a: int(p.a, 0, 200), souls: int(p.souls, 0, 400000),
                obj: int(p.obj, 0, 2000000), lvl: int(p.lvl, 0, 60) };
    if ([q.k, q.d, q.a, q.souls, q.obj, q.lvl].some((x) => x === null)) return "implausible stats for " + acc;
    m.players.push(q);
  }
  if (m.players.length < 4) return "not enough known players";
  const t0 = m.players.filter((p) => p.team === 0).length, t1 = m.players.length - t0;
  if (t0 > 6 || t1 > 6 || !t0 || !t1) return "bad teams";
  if (m.uploader && !seen.has(m.uploader)) return "uploader not in match";
  return m;
}

// ---------- routes ----------
async function upload(req, env) {
  const ip = req.headers.get("CF-Connecting-IP") || "?";
  if (limited(ip)) return json(req, { ok: false, error: "rate limited" }, 429);
  let body;
  try { body = await req.json(); } catch { return json(req, { ok: false, error: "bad json" }, 400); }
  const m = clean(body);
  if (typeof m === "string") return json(req, { ok: false, error: m }, 400);

  // fingerprint = who played on which side (written lowest-account-first, so every uploader gets the same one)
  const sideA = m.players.filter((p) => p.team === 0).map((p) => p.acc).sort((a, b) => a - b);
  const sideB = m.players.filter((p) => p.team === 1).map((p) => p.acc).sort((a, b) => a - b);
  const canon = sideB[0] < sideA[0];
  const fp = await sha((canon ? [sideB, sideA] : [sideA, sideB]).map((s) => s.join(",")).join("|"));

  // find the match: by Valve's match ID first, then by fingerprint (uploads from versions before 4.2 have no ID)
  let found = null;
  if (m.mid) found = await env.DB.prepare("SELECT key, start, src, mid FROM matches WHERE mid = ?").bind(m.mid).first();
  if (!found) {
    const f = await env.DB.prepare("SELECT key, start, src, mid FROM matches WHERE fp = ? ORDER BY start DESC LIMIT 1").bind(fp).first();
    // same players again much later = a new match; a different match ID = a different match
    if (f && Math.abs(f.start - m.start) <= 5400 && !(m.mid && f.mid && f.mid !== m.mid)) found = f;
  }
  const fresh = !found;
  const key = fresh ? fp + "-" + m.start : found.key;
  const start = fresh ? m.start : found.start;

  // which stored team is this uploader's "team 0"? Existing match: go by where its players are already stored.
  // New match: Team 1 / Team 2 as sent (4.2+), else the fingerprint order (older versions).
  let flip;
  if (!fresh) {
    const rows = (await env.DB.prepare("SELECT acc, team FROM players WHERE key = ?").bind(key).all()).results || [];
    const stored = {}; rows.forEach((r) => { stored[r.acc] = r.team; });
    let same = 0, diff = 0;
    for (const p of m.players) if (p.acc in stored) { if (stored[p.acc] === p.team) same++; else diff++; }
    flip = same || diff ? diff > same : (m.abs ? false : canon);
  } else flip = m.abs ? false : canon;
  const team = (rel) => (flip ? 1 - rel : rel);

  const who = m.uploader ? String(m.uploader) : "ip:" + (await sha(ip + "|ot")).slice(0, 16);
  // result is "did the uploader's team win": find the uploader's side (always team 0 for versions before 4.2)
  const me = m.players.find((p) => String(p.acc) === who);
  const myRel = me ? me.team : 0;
  const winTeam = m.result === null ? null : (m.result ? team(myRel) : 1 - team(myRel));
  const oldSrc = fresh ? 0 : (found.src || 0);
  const mode = m.src > oldSrc ? "replace" : m.src === oldSrc ? "max" : "fill";   // better data replaces, equal merges, worse only fills gaps

  const stmts = [];
  if (fresh) stmts.push(env.DB.prepare("INSERT OR IGNORE INTO matches (key, fp, start, dur, mode, updated, mid, ranked, src) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(key, fp, m.start, m.dur, m.mode, now(), m.mid, m.ranked, m.src));
  else {
    stmts.push(env.DB.prepare(`UPDATE matches SET updated = ?,
        dur = CASE WHEN ?2 > src OR ?3 > dur THEN ?3 ELSE dur END,
        mode = CASE WHEN mode = 'unknown' OR ?2 > src THEN CASE WHEN ?4 <> 'unknown' THEN ?4 ELSE mode END ELSE mode END,
        mid = COALESCE(mid, ?5), ranked = COALESCE(?6, ranked), src = MAX(src, ?2)
      WHERE key = ?7`).bind(now(), m.src, m.dur, m.mode, m.mid, m.ranked, key));
  }
  for (const p of m.players) {
    const vals = [key, p.acc, p.name, p.hero, team(p.team), p.k, p.d, p.a, p.souls, p.obj, p.lvl, start, p.hid, p.dmg, p.heal];
    const ins = "INSERT INTO players (key, acc, name, hero, team, k, d, a, souls, obj, lvl, start, hid, dmg, heal) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    if (mode === "replace") stmts.push(env.DB.prepare(ins + ` ON CONFLICT(key, acc) DO UPDATE SET name = excluded.name,
        hero = CASE WHEN excluded.hero <> '' THEN excluded.hero ELSE hero END, hid = COALESCE(excluded.hid, hid), team = excluded.team,
        k = excluded.k, d = excluded.d, a = excluded.a, souls = excluded.souls, obj = excluded.obj,
        lvl = CASE WHEN excluded.lvl > 0 THEN excluded.lvl ELSE lvl END,
        dmg = COALESCE(excluded.dmg, dmg), heal = COALESCE(excluded.heal, heal)`).bind(...vals));
    else if (mode === "max") stmts.push(env.DB.prepare(ins + ` ON CONFLICT(key, acc) DO UPDATE SET
        hero = CASE WHEN excluded.hero <> '' THEN excluded.hero ELSE hero END, hid = COALESCE(hid, excluded.hid),
        k = MAX(k, excluded.k), d = MAX(d, excluded.d), a = MAX(a, excluded.a), souls = MAX(souls, excluded.souls), obj = MAX(obj, excluded.obj), lvl = MAX(lvl, excluded.lvl)
      WHERE excluded.k > k OR excluded.d > d OR excluded.a > a OR excluded.souls > souls OR excluded.obj > obj OR excluded.lvl > lvl OR (hid IS NULL AND excluded.hid IS NOT NULL)`).bind(...vals));
    else stmts.push(env.DB.prepare(ins + ` ON CONFLICT(key, acc) DO UPDATE SET hid = COALESCE(hid, excluded.hid), dmg = COALESCE(dmg, excluded.dmg), heal = COALESCE(heal, excluded.heal)
      WHERE hid IS NULL OR dmg IS NULL OR heal IS NULL`).bind(...vals));
  }
  // one row per uploader per match; the result and the newest version / language / source are kept
  stmts.push(env.DB.prepare(`INSERT INTO uploads (key, uploader, result, ver, lang, src, left_early, t) VALUES (?, ?, NULL, ?, ?, ?, ?, ?)
      ON CONFLICT(key, uploader) DO UPDATE SET ver = COALESCE(excluded.ver, ver), lang = COALESCE(excluded.lang, lang),
        src = MAX(COALESCE(src, 0), excluded.src), left_early = MIN(COALESCE(left_early, 1), excluded.left_early), t = excluded.t`)
    .bind(key, who, m.ver, m.lang, m.src, m.left, now()));
  if (winTeam !== null) stmts.push(env.DB.prepare("UPDATE uploads SET result = ? WHERE key = ? AND uploader = ? AND (result IS NULL OR ? > 1)")
    .bind(winTeam, key, who, m.src >= SOURCES.postgame ? 2 : 0));
  stmts.push(env.DB.prepare(`UPDATE matches SET votes0 = (SELECT COUNT(*) FROM uploads WHERE key = ?1 AND result = 0),
                               votes1 = (SELECT COUNT(*) FROM uploads WHERE key = ?1 AND result = 1),
                               uploaders = (SELECT COUNT(*) FROM uploads WHERE key = ?1) WHERE key = ?1`).bind(key));
  const res = await env.DB.batch(stmts);
  const size = sizeOf(res[res.length - 1]);
  await trim(env, size);
  return json(req, { ok: true, merged: !fresh, key });
}

async function players(req, env, url) {
  const ids = (url.searchParams.get("ids") || "").split(",").map((x) => int(x, 1, 4294967295)).filter(Boolean).slice(0, 24);
  const limit = int(url.searchParams.get("limit"), 1, ids.length === 1 ? 5000 : 100) || 40;   // one player: their whole history
  if (!ids.length) return json(req, { players: {} });
  // newest matches per player, straight from the (acc, start) index: reads only what it returns
  const q = `SELECT p.key, p.acc, p.hero, p.team, p.k, p.d, p.a, p.souls, p.obj, p.lvl, p.start, m.dur, m.mode, m.votes0, m.votes1, m.uploaders
             FROM players p JOIN matches m ON m.key = p.key WHERE p.acc = ? ORDER BY p.start DESC LIMIT ?`;
  const res = await env.DB.batch(ids.map((id) => env.DB.prepare(q).bind(id, limit)));
  const out = {};
  res.forEach((r, i) => {
    const list = [];
    for (const row of r.results || []) {
      const win = row.votes0 > row.votes1 ? 0 : row.votes1 > row.votes0 ? 1 : null;
      // [start, dur, mode, hero, won(1/0/null), k, d, a, souls, obj, lvl, uploaders, key]
      list.push([row.start, row.dur, row.mode, row.hero, win === null ? null : (row.team === win ? 1 : 0), row.k, row.d, row.a, row.souls, row.obj, row.lvl, row.uploaders, row.key]);
    }
    // the same match can be stored twice (uploaders who knew different players): keep the best copy
    const best = list.slice().sort((x, y) => ((y[4] !== null) - (x[4] !== null)) || (y[1] - x[1]) || (y[11] - x[11]));
    const kept = [];
    for (const mm of best) if (!kept.some((k) => Math.abs(k[0] - mm[0]) < 1200)) kept.push(mm);
    if (kept.length) out[ids[i]] = kept.sort((x, y) => y[0] - x[0]);
  });
  return json(req, { players: out }, 200, { "Cache-Control": "public, max-age=120" });
}

// one stored match with its whole scoreboard
async function match(req, env, url) {
  let key = str(url.searchParams.get("key") || "", 80);
  const mid = str(url.searchParams.get("mid") || "", 16);
  if (/^\d{1,15}$/.test(mid)) {            // look up by Valve's match ID (v3)
    const r = await env.DB.prepare("SELECT key FROM matches WHERE mid = ?").bind(Number(mid)).first();
    if (!r) return json(req, { ok: false, error: "not found" }, 404);
    key = r.key;
  }
  if (!/^[0-9a-f-]{8,48}$/.test(key)) return json(req, { ok: false, error: "bad key" }, 400);
  const [m, p] = await env.DB.batch([
    env.DB.prepare("SELECT start, dur, mode, votes0, votes1, uploaders, mid, ranked, src FROM matches WHERE key = ?").bind(key),
    env.DB.prepare("SELECT acc, name, hero, hid, team, k, d, a, souls, obj, lvl, dmg, heal FROM players WHERE key = ?").bind(key),
  ]);
  const row = (m.results || [])[0];
  if (!row) return json(req, { ok: false, error: "not found" }, 404);
  const win = row.votes0 > row.votes1 ? 0 : row.votes1 > row.votes0 ? 1 : null;
  const SRC = ["unknown", "end screen (old)", "end of match", "post-game page"];
  return json(req, { ok: true, key, mid: row.mid ? String(row.mid) : null, ranked: row.ranked === null ? null : !!row.ranked, source: SRC[row.src || 0] || "unknown",
                     start: row.start, dur: row.dur, mode: row.mode, win, disputed: row.votes0 > 0 && row.votes1 > 0, uploaders: row.uploaders, players: p.results || [] },
              200, { "Cache-Control": "public, max-age=300" });
}

async function remove(req, env, acc) {
  if (!env.ADMIN_KEY || req.headers.get("X-Admin-Key") !== env.ADMIN_KEY) return json(req, { ok: false, error: "forbidden" }, 403);
  const id = int(acc, 1, 4294967295);
  if (!id) return json(req, { ok: false, error: "bad id" }, 400);
  const r = await env.DB.prepare("DELETE FROM players WHERE acc = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM uploads WHERE uploader = ?").bind(String(id)).run();
  return json(req, { ok: true, deleted: r.meta ? r.meta.changes : null });
}

// database size in bytes, from the last query's result (D1 reports it on every query)
function sizeOf(res) { const m = res && res.meta; return m && typeof m.size_after === "number" ? m.size_after : null; }
// Storage limit. SQLite doesn't shrink its file after deleting (it reuses the space), so the file size
// can't tell us when we're back under. Instead, the first time the file passes MAX_DB_MB we note how
// many matches fit ("cap", 90% of what's stored), and from then on the oldest matches are deleted
// whenever there are more than that. If the file still keeps growing past the limit, the cap is lowered.
// Match count = rowid range (rowids only go up and the oldest go first), so checking costs 2 index reads.
let capCache;            // per worker instance: undefined = not loaded yet
async function trim(env, size) {
  if (size === null) return;
  const max = MAX_DB_MB * 1024 * 1024;
  if (capCache === undefined) {
    const r = await env.DB.prepare("SELECT k, v FROM meta WHERE k IN ('cap', 'cap_size')").all();
    capCache = { cap: 0, at: 0 };
    for (const x of r.results || []) { if (x.k === "cap") capCache.cap = x.v; else capCache.at = x.v; }
  }
  if (!capCache.cap && size <= max) return;                      // plenty of room: nothing to read
  const rr = await env.DB.prepare("SELECT MIN(rowid) AS lo, MAX(rowid) AS hi FROM matches").first();
  if (!rr || !rr.hi) return;
  const count = rr.hi - rr.lo + 1;
  let cap = capCache.cap;
  if (size > max && (!cap || size > capCache.at * 1.02)) {       // first time full, or still growing: (re)set the cap
    cap = Math.max(100, Math.floor((cap ? Math.min(cap, count) : count) * 0.9));
    capCache = { cap, at: size };
    await env.DB.batch([
      env.DB.prepare("INSERT INTO meta (k, v) VALUES ('cap', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(cap),
      env.DB.prepare("INSERT INTO meta (k, v) VALUES ('cap_size', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(size),
    ]);
  }
  if (count <= cap) return;
  const n = Math.min(TRIM_MATCHES, count - cap);
  const old = "SELECT key FROM matches ORDER BY rowid ASC LIMIT " + n;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM players WHERE key IN (" + old + ")"),
    env.DB.prepare("DELETE FROM uploads WHERE key IN (" + old + ")"),
    env.DB.prepare("DELETE FROM matches WHERE key IN (" + old + ")"),
  ]);
}

// ---------- Ko-fi supporters ----------
// Ko-fi posts every payment here (form field "data" = JSON). Only the public name, whether it's a monthly
// membership, and the time are kept - no email, amount or message.
async function kofi(req, env) {
  if (!env.KOFI_TOKEN) return new Response("kofi off", { status: 200 });
  let d = null;
  try { const f = await req.formData(); d = JSON.parse(f.get("data") || "null"); } catch (e) { d = null; }
  if (!d || d.verification_token !== env.KOFI_TOKEN) return new Response("bad token", { status: 403 });
  const type = String(d.type || "");
  if (type !== "Donation" && type !== "Subscription") return new Response("ok", { status: 200 });   // shop orders, commissions
  const tx = str(String(d.kofi_transaction_id || d.message_id || ""), 80);
  if (!tx) return new Response("ok", { status: 200 });
  const name = d.is_public === false ? null : (str(d.from_name, 32) || null);
  const monthly = type === "Subscription" || d.is_subscription_payment === true ? 1 : 0;
  let t = Math.floor(Date.parse(d.timestamp || "") / 1000);
  if (!Number.isFinite(t) || t > now() + 600) t = now();
  await env.DB.prepare("INSERT OR IGNORE INTO supporters (tx, name, monthly, t) VALUES (?, ?, ?, ?)").bind(tx, name, monthly, t).run();
  supCache = null;
  return new Response("ok", { status: 200 });
}
// monthly = paid a membership in the last 35 days; once = a one-off tip in the last 31 days (and not monthly)
let supCache = null;
async function supporters(req, env) {
  if (supCache && Date.now() - supCache.at < 10 * 60 * 1000) return json(req, supCache.body, 200, { "Cache-Control": "public, max-age=600" });
  const r = await env.DB.prepare("SELECT name, monthly, MAX(t) AS t FROM supporters WHERE t > ? GROUP BY name, monthly ORDER BY t DESC LIMIT 200")
    .bind(now() - 35 * 86400).all();
  const monthly = [], once = [], seen = {};
  let privM = 0, privO = 0;
  for (const x of r.results || []) if (x.monthly) { if (x.name) { if (!seen[x.name]) { seen[x.name] = 1; monthly.push(x.name); } } else privM++; }
  for (const x of r.results || []) if (!x.monthly && x.t > now() - 31 * 86400) { if (x.name) { if (!seen[x.name]) { seen[x.name] = 1; once.push(x.name); } } else privO++; }
  const body = { ok: true, monthly, once, private_monthly: privM ? 1 : 0, private_once: privO ? 1 : 0 };
  supCache = { at: Date.now(), body };
  return json(req, body, 200, { "Cache-Control": "public, max-age=600" });
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
    if (!env.DB) return json(req, { ok: false, error: "D1 database not bound as DB" }, 500);
    try {
      await init(env);
      const url = new URL(req.url);
      const path = url.pathname.replace(/\/+$/, "");
      if (path === "" || path === "/health") {
        const r = await env.DB.prepare("SELECT MAX(rowid) AS n, MIN(start) AS oldest FROM matches").all();   // instant: rowid + start are indexed
        const c = (r.results || [])[0] || {}, size = sizeOf(r);
        return json(req, { ok: true, service: "orange-track-db", version: VERSION, matches_about: c.n || 0, oldest_match: c.oldest ? new Date(c.oldest * 1000).toISOString() : null,
                           size_mb: size === null ? null : Math.round(size / 1048576 * 10) / 10, limit_mb: MAX_DB_MB });
      }
      if (path === "/upload" && req.method === "POST") return await upload(req, env);
      if (path === "/kofi" && req.method === "POST") return await kofi(req, env);
      if (path === "/supporters" && req.method === "GET") return await supporters(req, env);
      if (path === "/players" && req.method === "GET") return await players(req, env, url);
      if (path === "/match" && req.method === "GET") return await match(req, env, url);
      const del = path.match(/^\/player\/(\d+)$/);
      if (del && req.method === "DELETE") return await remove(req, env, del[1]);
      return json(req, { ok: false, error: "not found" }, 404);
    } catch (e) {
      return json(req, { ok: false, error: String(e && e.message || e) }, 500);
    }
  },
};
