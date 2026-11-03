require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const { createProxyMiddleware } = require("http-proxy-middleware");

const app = express();

/* ------------------------------ config ------------------------------ */
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === "production";
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const MONGODB_URI = process.env.MONGODB_URI || "";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PUBLIC_DIR = path.join(__dirname, "public");
const RESERVED_PATHS = new Set(["api", "admin", "index", "favicon"]);

if (!process.env.SESSION_SECRET) console.warn("SESSION_SECRET is not set: admin sessions reset on every restart.");
if (!ADMIN_PASSWORD) console.warn("ADMIN_PASSWORD is not set: admin login is disabled.");

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(cookieParser());

const json = express.json({ limit: "100kb" }); // route-level only, so proxied request bodies stay untouched
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

/* ------------------------------ helpers ------------------------------ */
const httpError = (status, message) => Object.assign(new Error(message), { status });

let dbPromise = null;
function connectDB() {
  if (mongoose.connection.readyState === 1) return Promise.resolve();
  if (!MONGODB_URI) return Promise.reject(new Error("MONGODB_URI is not set."));
  if (!dbPromise) {
    dbPromise = mongoose
      .connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 })
      .then(() => console.log("MongoDB connected."))
      .catch((e) => { dbPromise = null; throw e; });
  }
  return dbPromise;
}

async function ensureDB(req, res, next) {
  try { await connectDB(); next(); }
  catch (e) {
    console.error("MongoDB error:", e.message);
    res.status(503).json({ success: false, error: "Database connection failed." });
  }
}

const projectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    path: { type: String, required: true, unique: true, trim: true },
    target: { type: String, required: true, trim: true },
    description: { type: String, default: "", trim: true },
    postUrl: { type: String, default: "", trim: true },
    image: { type: String, default: "" }, // data URL
    active: { type: Boolean, default: true },
  },
  { collection: "projects", timestamps: true }
);
const Project = mongoose.models.Project || mongoose.model("Project", projectSchema);

/* active projects cache for the proxy (avoids a DB query per asset request) */
let cache = { at: 0, list: [] };
const bustCache = () => { cache.at = 0; };
async function activeProjects() {
  if (Date.now() - cache.at < 15000) return cache.list;
  await connectDB();
  cache = { at: Date.now(), list: await Project.find({ active: true }).select("path target").lean() };
  return cache.list;
}

async function listProjects(match, { admin }) {
  const hide = admin ? { image: 0 } : { image: 0, target: 0 };
  const rows = await Project.aggregate([
    { $match: match },
    { $sort: { createdAt: -1 } },
    { $addFields: { hasImage: { $gt: [{ $strLenCP: { $ifNull: ["$image", ""] } }, 0] } } },
    { $project: hide },
  ]);
  return rows.map((p) => ({
    ...p,
    imageUrl: p.hasImage
      ? `/api/project-image/${p._id}?v=${new Date(p.updatedAt || p.createdAt).getTime()}`
      : "",
  }));
}

function sniffImage(b) {
  if (b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8) return "image/jpeg";
  if (b.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex"))) return "image/png";
  if (b.subarray(0, 3).toString() === "GIF") return "image/gif";
  if (b.subarray(0, 4).toString() === "RIFF" && b.subarray(8, 12).toString() === "WEBP") return "image/webp";
  return null;
}
function readImage(file) {
  if (!file) return "";
  const mime = sniffImage(file.buffer);
  if (!mime) throw httpError(400, "Only JPG, PNG, WEBP and GIF images are allowed.");
  return `data:${mime};base64,${file.buffer.toString("base64")}`;
}

function parseFields(b, partial) {
  const out = {};
  if (!partial || b.name !== undefined) {
    const v = String(b.name || "").trim();
    if (!v) throw httpError(400, "Project name is required.");
    out.name = v;
  }
  if (!partial || b.path !== undefined) {
    let p = String(b.path || "").trim();
    if (!p.startsWith("/")) p = "/" + p;
    p = p.replace(/\/+$/, "");
    if (!/^\/[a-zA-Z0-9_-]+$/.test(p)) throw httpError(400, "Path must look like /bot, /pair or /host.");
    if (RESERVED_PATHS.has(p.slice(1).toLowerCase())) throw httpError(400, "This path is reserved by the site.");
    out.path = p;
  }
  if (!partial || b.target !== undefined) {
    let u;
    try { u = new URL(String(b.target || "").trim()); } catch { throw httpError(400, "Invalid target URL."); }
    if (!/^https?:$/.test(u.protocol)) throw httpError(400, "Target must start with http:// or https://");
    out.target = u.origin;
  }
  if (b.description !== undefined) out.description = String(b.description).trim().slice(0, 400);
  if (b.postUrl !== undefined) {
    const v = String(b.postUrl).trim();
    if (v) {
      let ok = false;
      try { ok = /^https?:$/.test(new URL(v).protocol); } catch {}
      if (!ok) throw httpError(400, "Post link must be a valid http(s) URL.");
    }
    out.postUrl = v;
  }
  if (b.active !== undefined) out.active = String(b.active) !== "false";
  return out;
}

/* ------------------------------ admin auth ------------------------------ */
const COOKIE = { httpOnly: true, secure: isProd, sameSite: "strict", path: "/" };
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (s) => crypto.createHmac("sha256", SESSION_SECRET).update(s).digest("base64url");

function createToken(username) {
  const body = Buffer.from(JSON.stringify({ username, exp: Date.now() + 864e5 })).toString("base64url");
  return `${body}.${sign(body)}`;
}
function verifyToken(token) {
  try {
    const [body, sig, extra] = String(token || "").split(".");
    if (!body || !sig || extra !== undefined || !safeEqual(sig, sign(body))) return false;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() && p.username === ADMIN_USERNAME;
  } catch { return false; }
}
const isAdmin = (req) => verifyToken(req.cookies.sila_admin);
const requireAdmin = (req, res, next) =>
  isAdmin(req) ? next() : res.status(401).json({ success: false, error: "Unauthorized" });

const tries = new Map();
const isLocked = (ip) => {
  const r = tries.get(ip);
  if (!r) return false;
  if (Date.now() - r.t > 15 * 60 * 1000) { tries.delete(ip); return false; }
  return r.n >= 8;
};
const failTry = (ip) => {
  const r = tries.get(ip) || { n: 0, t: Date.now() };
  r.n++;
  tries.set(ip, r);
};

/* ------------------------------ api ------------------------------ */
app.get("/api/health", async (req, res) => {
  try { await connectDB(); res.json({ success: true, status: "online", database: "connected", time: new Date().toISOString() }); }
  catch (e) { res.status(503).json({ success: false, status: "offline", database: "disconnected" }); }
});

app.post("/api/login", json, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ success: false, error: "ADMIN_PASSWORD is not set on the server." });
  if (isLocked(req.ip)) return res.status(429).json({ success: false, error: "Too many attempts. Try again in 15 minutes." });
  const { username, password } = req.body || {};
  const okUser = safeEqual(String(username || ""), ADMIN_USERNAME);
  const okPass = safeEqual(String(password || ""), ADMIN_PASSWORD);
  if (!(okUser && okPass)) {
    failTry(req.ip);
    return res.status(401).json({ success: false, error: "Wrong username or password." });
  }
  tries.delete(req.ip);
  res.cookie("sila_admin", createToken(ADMIN_USERNAME), { ...COOKIE, maxAge: 864e5 });
  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("sila_admin", COOKIE);
  res.json({ success: true });
});

app.get("/api/me", (req, res) => res.json({ authenticated: isAdmin(req) }));

app.get("/api/projects", ensureDB, async (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ success: true, projects: await listProjects({ active: true }, { admin: false }) });
});

app.get("/api/project-image/:id", ensureDB, async (req, res) => {
  const p = await Project.findById(req.params.id).select("image active").lean();
  if (!p || !p.image || (!p.active && !isAdmin(req))) throw httpError(404, "Image not found.");
  const m = /^data:(image\/[a-z]+);base64,(.+)$/s.exec(p.image);
  if (!m) throw httpError(404, "Image not found.");
  res.set({
    "Content-Type": m[1],
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": req.query.v ? "public, max-age=31536000, immutable" : "public, max-age=300",
  });
  res.send(Buffer.from(m[2], "base64"));
});

app.get("/api/admin/projects", ensureDB, requireAdmin, async (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ success: true, projects: await listProjects({}, { admin: true }) });
});

app.post("/api/admin/projects", ensureDB, requireAdmin, upload.single("image"), async (req, res) => {
  const data = parseFields(req.body, false);
  const project = await Project.create({ ...data, image: readImage(req.file) });
  bustCache();
  res.status(201).json({ success: true, id: project._id });
});

app.put("/api/admin/projects/:id", ensureDB, requireAdmin, upload.single("image"), async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) throw httpError(404, "Project not found.");
  Object.assign(project, parseFields(req.body, true));
  if (req.file) project.image = readImage(req.file);
  else if (req.body.removeImage === "true") project.image = "";
  await project.save();
  bustCache();
  res.json({ success: true });
});

app.patch("/api/admin/projects/:id/toggle", ensureDB, requireAdmin, async (req, res) => {
  const project = await Project.findById(req.params.id);
  if (!project) throw httpError(404, "Project not found.");
  project.active = !project.active;
  await project.save();
  bustCache();
  res.json({ success: true, active: project.active });
});

app.delete("/api/admin/projects/:id", ensureDB, requireAdmin, async (req, res) => {
  const project = await Project.findByIdAndDelete(req.params.id);
  if (!project) throw httpError(404, "Project not found.");
  bustCache();
  res.json({ success: true });
});

/* ------------------------------ site files ------------------------------ */
app.use(
  express.static(PUBLIC_DIR, {
    setHeaders: (res, file) => {
      res.set("X-Content-Type-Options", "nosniff");
      if (file.endsWith("admin.html")) res.set("X-Robots-Tag", "noindex, nofollow");
    },
  })
);
app.get("/admin", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "admin.html")));

/* ------------------------------ dynamic reverse proxy ------------------------------ */
// silatech.site/bot/login  ->  <project target>/login
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const firstSegment = (p) => (String(p || "").split("?")[0].split("/").filter(Boolean)[0] || null);

const dynamicProxy = createProxyMiddleware({
  target: "http://127.0.0.1:3000",
  changeOrigin: true,
  cookieDomainRewrite: "",
  followRedirects: false,
  proxyTimeout: 30000,
  timeout: 35000,
  headers: { "x-forwarded-by": "SILA-TECH" },
  router: (req) => (req.silaProject ? req.silaProject.target : "http://127.0.0.1:3000"),
  pathRewrite: (reqPath, req) => {
    const project = req.silaProject;
    if (!project || req.silaStripPrefix === false) return reqPath;
    const rest = reqPath.replace(new RegExp("^" + escapeRegExp(project.path)), "");
    return rest.startsWith("/") ? rest : "/" + rest;
  },
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader("x-sila-proxy", "SILA-TECH");
      proxyReq.setHeader("x-forwarded-host", req.headers.host || "");
      // never leak the admin session to a proxied app
      if (req.headers.cookie) {
        const kept = req.headers.cookie.split(/;\s*/).filter((c) => !c.startsWith("sila_admin="));
        if (kept.length) proxyReq.setHeader("cookie", kept.join("; "));
        else proxyReq.removeHeader("cookie");
      }
    },
    proxyRes: (proxyRes, req) => {
      const loc = proxyRes.headers.location;
      const project = req.silaProject;
      if (!loc || !project) return;
      try {
        const origin = new URL(project.target).origin;
        if (loc.startsWith(origin)) proxyRes.headers.location = loc.replace(origin, BASE_URL + project.path);
        else if (loc.startsWith("/") && !loc.startsWith("//") && req.silaStripPrefix !== false)
          proxyRes.headers.location = project.path + loc;
      } catch (e) { console.error("Location rewrite error:", e.message); }
    },
    error: (err, req, res) => {
      console.error("Proxy error:", err.message);
      if (res && !res.headersSent) {
        res.statusCode = 502;
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.end(`<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SILA TECH</title>
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#eef3f6;color:#0a2540;font-family:system-ui,sans-serif">
<div style="max-width:420px;padding:32px;text-align:center"><h1 style="margin:0 0 8px">This project is not responding</h1>
<p style="color:#5b6b7f;margin:0 0 20px">The server behind this page didn’t answer. Try again in a moment.</p>
<a href="/" style="color:#1f4bff;font-weight:600">Back to SILA TECH</a></div></body>`);
      }
    },
  },
});

app.use(async (req, res, next) => {
  const pathname = req.path;
  if (pathname.startsWith("/api/") || pathname === "/admin") return next();
  const first = firstSegment(pathname);
  if (!first) return next();

  let list;
  try { list = await activeProjects(); }
  catch (e) { return res.status(503).type("text").send("SILA TECH: database unavailable."); }

  let project = list.find((p) => p.path === "/" + first);
  let strip = true;

  // sub-apps often call absolute paths (e.g. /api/pairing-code); recover the project from the Referer
  if (!project && req.headers["sec-fetch-dest"] !== "document") {
    try {
      const ref = new URL(req.headers.referer || "");
      const refFirst = ref.host === req.headers.host ? firstSegment(ref.pathname) : null;
      if (refFirst) project = list.find((p) => p.path === "/" + refFirst);
      if (project) strip = false;
    } catch {}
  }
  if (!project) return next();

  req.silaProject = project;
  req.silaStripPrefix = strip;
  return dynamicProxy(req, res, next);
});

/* ------------------------------ fallbacks ------------------------------ */
app.get("/{*splat}", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});
app.use("/api", (req, res) => res.status(404).json({ success: false, error: "API route not found." }));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  let status = err.status || 500;
  let message = err.message || "Internal server error.";
  if (err instanceof multer.MulterError) {
    status = 400;
    if (err.code === "LIMIT_FILE_SIZE") message = "Image must be 2 MB or smaller.";
  } else if (err.code === 11000) { status = 409; message = "A project with this path already exists."; }
  else if (err.name === "CastError") { status = 404; message = "Not found."; }
  else if (err.type === "entity.parse.failed") { status = 400; message = "Invalid request body."; }
  if (status >= 500) console.error("ERROR:", err);
  res.status(status).json({ success: false, error: status >= 500 && isProd ? "Internal server error." : message });
});

/* ------------------------------ start ------------------------------ */
if (process.env.VERCEL !== "1") {
  app.listen(PORT, () => console.log(`SILA TECH running on port ${PORT}`));
  connectDB().catch((e) => console.error("MongoDB connection error:", e.message));
}

module.exports = app;
