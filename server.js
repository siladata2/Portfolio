require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const {
  createProxyMiddleware,
} = require("http-proxy-middleware");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const BASE_URL = (
  process.env.BASE_URL ||
  "http://localhost:3000"
).replace(/\/+$/, "");

const SESSION_SECRET =
  process.env.SESSION_SECRET || "CHANGE_THIS_SECRET";

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || "admin";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "CHANGE_THIS_PASSWORD";

/* =========================================================
   MONGODB CONNECTION
========================================================= */

let mongoConnection = null;

async function connectDB() {
  if (mongoConnection) {
    return mongoConnection;
  }

  if (!process.env.MONGODB_URI) {
    throw new Error(
      "MONGODB_URI is missing in environment variables."
    );
  }

  mongoConnection = mongoose.connect(
    process.env.MONGODB_URI,
    {
      serverSelectionTimeoutMS: 10000,
    }
  );

  await mongoConnection;

  console.log("MongoDB connected.");

  return mongoConnection;
}

/* =========================================================
   PROJECT MODEL
========================================================= */

const projectSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    path: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    target: {
      type: String,
      required: true,
      trim: true,
    },

    description: {
      type: String,
      default: "",
      trim: true,
    },

    postUrl: {
      type: String,
      default: "",
      trim: true,
    },

    /*
      Image stored as Data URL.

      Example:
      data:image/jpeg;base64,/9j/4AAQ...

      This avoids relying on Vercel's temporary filesystem.
    */
    image: {
      type: String,
      default: "",
    },

    active: {
      type: Boolean,
      default: true,
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "projects",
  }
);

const Project =
  mongoose.models.Project ||
  mongoose.model("Project", projectSchema);

/* =========================================================
   MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.use(cookieParser());

/*
  Vercel Functions have request payload limits.
  Keep normal JSON requests small.
*/
app.use(
  express.json({
    limit: "4mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "4mb",
  })
);

/* =========================================================
   MULTER
========================================================= */

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB
  },

  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error(
          "Only JPG, PNG, WEBP and GIF images are allowed."
        )
      );
    }

    cb(null, true);
  },
});

/* =========================================================
   DATABASE HELPER
========================================================= */

async function ensureDB(req, res, next) {
  try {
    await connectDB();
    next();
  } catch (error) {
    console.error(
      "MongoDB connection error:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error: "Database connection failed.",
      message:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
}

/* =========================================================
   ADMIN AUTH
========================================================= */

function createAdminToken(username) {
  const payload = {
    username,
    exp: Date.now() + 24 * 60 * 60 * 1000,
  };

  const encoded = Buffer.from(
    JSON.stringify(payload)
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyAdminToken(token) {
  try {
    if (!token) return false;

    const parts = token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const [encoded, signature] = parts;

    const expectedSignature = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(encoded)
      .digest("base64url");

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      )
    ) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString()
    );

    if (!payload.username) {
      return false;
    }

    if (payload.exp < Date.now()) {
      return false;
    }

    if (payload.username !== ADMIN_USERNAME) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const token = req.cookies.sila_admin;

  if (!verifyAdminToken(token)) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized",
    });
  }

  next();
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await connectDB();

    res.json({
      success: true,
      status: "online",
      database: "connected",
      service: "SILA TECH",
      time: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      status: "offline",
      database: "disconnected",
      error: error.message,
    });
  }
});

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username and password are required.",
      });
    }

    if (
      username !== ADMIN_USERNAME ||
      password !== ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        success: false,
        error: "Invalid username or password.",
      });
    }

    const token = createAdminToken(username);

    res.cookie("sila_admin", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.json({
      success: true,
      message: "Login successful.",
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      error: "Login failed.",
    });
  }
});

/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
  res.clearCookie("sila_admin", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });

  return res.json({
    success: true,
    message: "Logged out.",
  });
});

/* =========================================================
   CHECK ADMIN
========================================================= */

app.get("/api/me", (req, res) => {
  const token = req.cookies.sila_admin;

  if (!verifyAdminToken(token)) {
    return res.json({
      authenticated: false,
    });
  }

  return res.json({
    authenticated: true,
    username: ADMIN_USERNAME,
  });
});

/* =========================================================
   PUBLIC PROJECTS
========================================================= */

app.get(
  "/api/projects",
  ensureDB,
  async (req, res) => {
    try {
      const projects = await Project.find({
        active: true,
      })
        .sort({
          createdAt: -1,
        })
        .lean();

      return res.json({
        success: true,
        projects,
      });
    } catch (error) {
      console.error(
        "Projects error:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Failed to load projects.",
      });
    }
  }
);

/* =========================================================
   ADMIN - GET ALL PROJECTS
========================================================= */

app.get(
  "/api/admin/projects",
  ensureDB,
  requireAdmin,
  async (req, res) => {
    try {
      const projects = await Project.find({})
        .sort({
          createdAt: -1,
        })
        .lean();

      return res.json({
        success: true,
        projects,
      });
    } catch (error) {
      console.error(
        "Admin projects error:",
        error
      );

      return res.status(500).json({
        success: false,
        error: "Failed to load projects.",
      });
    }
  }
);

/* =========================================================
   IMAGE CONVERTER
========================================================= */

function imageToDataURL(file) {
  if (!file || !file.buffer) {
    return "";
  }

  return `data:${file.mimetype};base64,${file.buffer.toString(
    "base64"
  )}`;
}

/* =========================================================
   ADMIN - CREATE PROJECT
========================================================= */

app.post(
  "/api/admin/projects",
  ensureDB,
  requireAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      let {
        name,
        path: projectPath,
        target,
        description,
        postUrl,
        active,
      } = req.body;

      if (!name) {
        return res.status(400).json({
          success: false,
          error: "Project name is required.",
        });
      }

      if (!projectPath) {
        return res.status(400).json({
          success: false,
          error: "Project path is required.",
        });
      }

      if (!target) {
        return res.status(400).json({
          success: false,
          error: "Target URL is required.",
        });
      }

      /* -----------------------------------------
         NORMALIZE PATH
      ----------------------------------------- */

      projectPath = projectPath.trim();

      if (!projectPath.startsWith("/")) {
        projectPath = "/" + projectPath;
      }

      projectPath = projectPath.replace(
        /\/+$/,
        ""
      );

      /* -----------------------------------------
         VALIDATE PATH
      ----------------------------------------- */

      if (
        !/^\/[a-zA-Z0-9_-]+$/.test(
          projectPath
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Path must look like /bot, /pair or /host.",
        });
      }

      /* -----------------------------------------
         VALIDATE TARGET
      ----------------------------------------- */

      let targetUrl;

      try {
        targetUrl = new URL(target.trim());
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: "Invalid target URL.",
        });
      }

      if (
        !["http:", "https:"].includes(
          targetUrl.protocol
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Target must use http:// or https://",
        });
      }

      const existing = await Project.findOne({
        path: projectPath,
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          error:
            "A project with this path already exists.",
        });
      }

      /* -----------------------------------------
         IMAGE
      ----------------------------------------- */

      const image = imageToDataURL(
        req.file
      );

      /* -----------------------------------------
         CREATE
      ----------------------------------------- */

      const project =
        await Project.create({
          name: name.trim(),

          path: projectPath,

          target: targetUrl.origin,

          description:
            description?.trim() || "",

          postUrl:
            postUrl?.trim() || "",

          image,

          active:
            active === "false"
              ? false
              : true,
        });

      return res.status(201).json({
        success: true,
        message: "Project created successfully.",
        project,
      });
    } catch (error) {
      console.error(
        "Create project error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Failed to create project.",
      });
    }
  }
);

/* =========================================================
   ADMIN - UPDATE PROJECT
========================================================= */

app.put(
  "/api/admin/projects/:id",
  ensureDB,
  requireAdmin,
  upload.single("image"),
  async (req, res) => {
    try {
      const project =
        await Project.findById(
          req.params.id
        );

      if (!project) {
        return res.status(404).json({
          success: false,
          error: "Project not found.",
        });
      }

      let {
        name,
        path: projectPath,
        target,
        description,
        postUrl,
        active,
      } = req.body;

      if (name !== undefined) {
        project.name = name.trim();
      }

      if (projectPath !== undefined) {
        projectPath =
          projectPath.trim();

        if (
          !projectPath.startsWith("/")
        ) {
          projectPath =
            "/" + projectPath;
        }

        projectPath =
          projectPath.replace(
            /\/+$/,
            ""
          );

        if (
          !/^\/[a-zA-Z0-9_-]+$/.test(
            projectPath
          )
        ) {
          return res.status(400).json({
            success: false,
            error:
              "Invalid project path.",
          });
        }

        const duplicate =
          await Project.findOne({
            path: projectPath,
            _id: {
              $ne: project._id,
            },
          });

        if (duplicate) {
          return res.status(409).json({
            success: false,
            error:
              "Another project already uses this path.",
          });
        }

        project.path =
          projectPath;
      }

      if (target !== undefined) {
        try {
          const parsedTarget =
            new URL(target.trim());

          if (
            !["http:", "https:"].includes(
              parsedTarget.protocol
            )
          ) {
            throw new Error(
              "Invalid protocol"
            );
          }

          project.target =
            parsedTarget.origin;
        } catch (error) {
          return res.status(400).json({
            success: false,
            error:
              "Invalid target URL.",
          });
        }
      }

      if (
        description !== undefined
      ) {
        project.description =
          description.trim();
      }

      if (postUrl !== undefined) {
        project.postUrl =
          postUrl.trim();
      }

      if (active !== undefined) {
        project.active =
          active !== "false";
      }

      if (req.file) {
        project.image =
          imageToDataURL(
            req.file
          );
      }

      await project.save();

      return res.json({
        success: true,
        message:
          "Project updated successfully.",
        project,
      });
    } catch (error) {
      console.error(
        "Update project error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Failed to update project.",
      });
    }
  }
);

/* =========================================================
   ADMIN - DELETE PROJECT
========================================================= */

app.delete(
  "/api/admin/projects/:id",
  ensureDB,
  requireAdmin,
  async (req, res) => {
    try {
      const project =
        await Project.findByIdAndDelete(
          req.params.id
        );

      if (!project) {
        return res.status(404).json({
          success: false,
          error: "Project not found.",
        });
      }

      return res.json({
        success: true,
        message:
          "Project deleted successfully.",
      });
    } catch (error) {
      console.error(
        "Delete project error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Failed to delete project.",
      });
    }
  }
);

/* =========================================================
   ADMIN - TOGGLE PROJECT
========================================================= */

app.patch(
  "/api/admin/projects/:id/toggle",
  ensureDB,
  requireAdmin,
  async (req, res) => {
    try {
      const project =
        await Project.findById(
          req.params.id
        );

      if (!project) {
        return res.status(404).json({
          success: false,
          error: "Project not found.",
        });
      }

      project.active =
        !project.active;

      await project.save();

      return res.json({
        success: true,
        active: project.active,
      });
    } catch (error) {
      console.error(
        "Toggle error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Failed to toggle project.",
      });
    }
  }
);

/* =========================================================
   DYNAMIC REVERSE PROXY
========================================================= */

/*
  Example:

  Browser:
  https://silatech.site/bot

  MongoDB:
  path   = /bot
  target = https://example.herokuapp.com

  Request becomes:
  https://example.herokuapp.com/

  --------------------------------------------

  Browser:
  https://silatech.site/bot/login

  becomes:

  https://example.herokuapp.com/login
*/

const dynamicProxy =
  createProxyMiddleware({
    target: "http://127.0.0.1:3000",

    changeOrigin: true,

    /*
      We dynamically choose the target
      from MongoDB.
    */
    router: async (req) => {
      try {
        await connectDB();

        const firstPart =
          getProjectPathFromRequest(
            req.path
          );

        if (!firstPart) {
          return "http://127.0.0.1:3000";
        }

        const project =
          await Project.findOne({
            path: firstPart,
            active: true,
          }).lean();

        if (!project) {
          return "http://127.0.0.1:3000";
        }

        req.silaProject =
          project;

        return project.target;
      } catch (error) {
        console.error(
          "Proxy router error:",
          error
        );

        return "http://127.0.0.1:3000";
      }
    },

    /*
      Remove /bot /pair /host
      before sending request
      to target server.
    */
    pathRewrite: (requestPath, req) => {
      const project =
        req.silaProject;

      if (!project) {
        return requestPath;
      }

      const projectPath =
        project.path;

      let newPath =
        requestPath.replace(
          new RegExp(
            "^" +
              escapeRegExp(
                projectPath
              )
          ),
          ""
        );

      if (!newPath) {
        newPath = "/";
      }

      if (!newPath.startsWith("/")) {
        newPath =
          "/" + newPath;
      }

      return newPath;
    },

    /*
      Fix cookies from target domain
      so they work on SILA TECH domain.
    */
    cookieDomainRewrite: "",

    /*
      Make redirects from upstream
      return through SILA TECH.
    */
    followRedirects: false,

    /*
      Timeouts.
    */
    proxyTimeout: 30000,

    timeout: 35000,

    /*
      Avoid automatic compression problems
      while proxying.
    */
    headers: {
      "x-forwarded-by": "SILA-TECH",
    },

    on: {
      proxyReq: (proxyReq, req) => {
        proxyReq.setHeader(
          "x-sila-proxy",
          "SILA-TECH"
        );

        proxyReq.setHeader(
          "x-forwarded-host",
          req.headers.host || ""
        );
      },

      proxyRes: (proxyRes, req) => {
        /*
          Rewrite Location headers so
          redirects stay under the
          SILA TECH project path.
        */

        const location =
          proxyRes.headers.location;

        const project =
          req.silaProject;

        if (
          location &&
          project
        ) {
          try {
            const targetUrl =
              new URL(
                project.target
              );

            if (
              location.startsWith(
                targetUrl.origin
              )
            ) {
              const newLocation =
                location.replace(
                  targetUrl.origin,
                  `${BASE_URL}${project.path}`
                );

              proxyRes.headers.location =
                newLocation;
            }
          } catch (error) {
            console.error(
              "Location rewrite error:",
              error.message
            );
          }
        }
      },

      error: (err, req, res) => {
        console.error(
          "Proxy error:",
          err.message
        );

        if (
          res &&
          !res.headersSent
        ) {
          res.statusCode = 502;

          res.setHeader(
            "Content-Type",
            "text/html; charset=utf-8"
          );

          res.end(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SILA TECH - Proxy Error</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  background:#05070d;
  color:white;
  font-family:Arial,sans-serif;
}
.box{
  width:min(90%,600px);
  padding:35px;
  border:1px solid #1e40af;
  border-radius:18px;
  background:#0b1020;
  box-shadow:0 0 40px rgba(30,64,175,.25);
  text-align:center;
}
h1{
  color:#60a5fa;
}
p{
  color:#aab4c8;
}
</style>
</head>
<body>
<div class="box">
<h1>SILA TECH</h1>
<p>Unable to connect to the project server.</p>
<p>Please check the target URL in the admin panel.</p>
</div>
</body>
</html>
          `);
        }
      },
    },
  });

/* =========================================================
   PROJECT PATH DETECTION
========================================================= */

function getProjectPathFromRequest(
  requestPath
) {
  if (!requestPath) {
    return null;
  }

  const clean =
    requestPath.split("?")[0];

  const parts =
    clean.split("/").filter(Boolean);

  if (!parts.length) {
    return null;
  }

  return "/" + parts[0];
}

/* =========================================================
   REGEX ESCAPE
========================================================= */

function escapeRegExp(string) {
  return string.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );
}

/* =========================================================
   PROJECT PROXY ROUTE
========================================================= */

/*
  We don't proxy:
  /api/*
  /admin.html
  /style.css
  /app.js
  /uploads/*
*/

app.use(async (req, res, next) => {
  try {
    const pathname =
      req.path || "/";

    if (
      pathname.startsWith("/api/")
    ) {
      return next();
    }

    if (
      pathname === "/admin.html"
    ) {
      return next();
    }

    if (
      pathname === "/style.css" ||
      pathname === "/app.js" ||
      pathname.startsWith(
        "/favicon"
      )
    ) {
      return next();
    }

    const firstPart =
      getProjectPathFromRequest(
        pathname
      );

    if (!firstPart) {
      return next();
    }

    await connectDB();

    const project =
      await Project.findOne({
        path: firstPart,
        active: true,
      }).lean();

    if (!project) {
      return next();
    }

    /*
      Save project on request so
      router/pathRewrite can use it.
    */
    req.silaProject =
      project;

    return dynamicProxy(
      req,
      res,
      next
    );
  } catch (error) {
    console.error(
      "Dynamic proxy middleware error:",
      error
    );

    return res.status(500).send(
      "SILA TECH proxy error."
    );
  }
});

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =========================================================
   ADMIN PAGE
========================================================= */

app.get(
  "/admin",
  (req, res) => {
    return res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

/*
  IMPORTANT:
  Express 5 uses:
  
  /{*splat}

  NOT:
  
  *
*/

app.get(
  "/{*splat}",
  (req, res) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res.status(404).json({
        success: false,
        error: "API route not found.",
      });
    }

    return res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {
    console.error(
      "GLOBAL ERROR:",
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    return res.status(500).json({
      success: false,
      error:
        err.message ||
        "Internal server error.",
    });
  }
);

/* =========================================================
   LOCAL SERVER
========================================================= */

/*
  Vercel handles the app itself.

  Locally:
  npm start
*/
if (
  process.env.VERCEL !== "1"
) {
  connectDB()
    .then(() => {
      app.listen(
        PORT,
        () => {
          console.log(
            `SILA TECH running on port ${PORT}`
          );

          console.log(
            `Local: http://localhost:${PORT}`
          );
        }
      );
    })
    .catch((error) => {
      console.error(
        "Startup failed:",
        error
      );

      process.exit(1);
    });
}

/* =========================================================
   VERCEL / NODE EXPORT
========================================================= */

module.exports = app;