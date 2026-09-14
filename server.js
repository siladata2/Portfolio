require("dotenv").config();

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const {
  createProxyMiddleware,
  responseInterceptor
} = require("http-proxy-middleware");

const app = express();

const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "CHANGE_ME",
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 12
    }
  })
);


// =====================================================
// UPLOADS
// =====================================================

const uploadDir = path.join(
  __dirname,
  "public",
  "uploads"
);

fs.mkdirSync(uploadDir, {
  recursive: true
});


const storage = multer.diskStorage({

  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },

  filename: function (req, file, cb) {

    const ext = path
      .extname(file.originalname)
      .toLowerCase();

    const name = path
      .basename(file.originalname, ext)
      .replace(/[^a-z0-9-_]/gi, "-")
      .slice(0, 50);

    cb(
      null,
      Date.now() +
        "-" +
        (name || "post") +
        ext
    );
  }

});


const upload = multer({

  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: function (req, file, cb) {

    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error(
          "Only JPG, PNG, WEBP and GIF images are allowed."
        )
      );
    }

    cb(null, true);
  }

});


// =====================================================
// DATABASE
// =====================================================

const projectSchema = new mongoose.Schema({

  name: {
    type: String,
    required: true,
    trim: true
  },

  path: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },

  target: {
    type: String,
    required: true,
    trim: true
  },

  description: {
    type: String,
    default: "",
    trim: true
  },

  postUrl: {
    type: String,
    default: "",
    trim: true
  },

  image: {
    type: String,
    default: ""
  },

  active: {
    type: Boolean,
    default: true
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});


const Project = mongoose.model(
  "Project",
  projectSchema
);


// =====================================================
// HELPERS
// =====================================================

function cleanPath(value) {

  let p = String(value || "").trim();

  if (!p.startsWith("/")) {
    p = "/" + p;
  }

  p = p.replace(/\s+/g, "-");

  p = p.replace(/\/+/g, "/");

  if (p.length > 1) {
    p = p.replace(/\/$/, "");
  }

  return p;
}


function validTarget(value) {

  try {

    const url = new URL(value);

    return (
      url.protocol === "https:" ||
      url.protocol === "http:"
    );

  } catch {

    return false;

  }

}


// =====================================================
// ADMIN AUTH
// =====================================================

function adminOnly(req, res, next) {

  if (req.session.admin) {
    return next();
  }

  return res
    .status(401)
    .json({
      error: "Unauthorized"
    });

}


// =====================================================
// PUBLIC FILES
// =====================================================

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


// =====================================================
// PUBLIC PROJECTS
// =====================================================

app.get(
  "/api/projects",
  async (req, res) => {

    try {

      const projects =
        await Project.find({
          active: true
        })
        .sort({
          createdAt: -1
        })
        .select("-target");

      res.json(projects);

    } catch (error) {

      console.error(error);

      res
        .status(500)
        .json({
          error: "Failed to load projects"
        });

    }

  }
);


// =====================================================
// LOGIN
// =====================================================

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const {
        username,
        password
      } = req.body;

      const adminUsername =
        process.env.ADMIN_USERNAME;

      const adminPassword =
        process.env.ADMIN_PASSWORD;

      if (
        !adminUsername ||
        !adminPassword
      ) {

        return res
          .status(500)
          .json({
            error:
              "Admin credentials are not configured."
          });

      }


      if (
        username !== adminUsername ||
        password !== adminPassword
      ) {

        return res
          .status(401)
          .json({
            error:
              "Invalid username or password."
          });

      }


      req.session.admin = true;

      res.json({
        ok: true
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error: "Login failed."
        });

    }

  }
);


// =====================================================
// LOGOUT
// =====================================================

app.post(
  "/api/logout",
  adminOnly,
  (req, res) => {

    req.session.destroy(
      function () {

        res.json({
          ok: true
        });

      }
    );

  }
);


// =====================================================
// ADMIN GET PROJECTS
// =====================================================

app.get(
  "/api/admin/projects",
  adminOnly,
  async (req, res) => {

    try {

      const projects =
        await Project.find()
        .sort({
          createdAt: -1
        });

      res.json(projects);

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            "Failed to load projects."
        });

    }

  }
);


// =====================================================
// ADMIN ADD PROJECT
// =====================================================

app.post(
  "/api/admin/projects",
  adminOnly,
  upload.single("image"),

  async (req, res) => {

    try {

      const {
        name,
        target,
        description,
        postUrl
      } = req.body;


      const projectPath =
        cleanPath(req.body.path);


      if (!name) {

        return res
          .status(400)
          .json({
            error:
              "Project name is required."
          });

      }


      if (!target) {

        return res
          .status(400)
          .json({
            error:
              "Target URL is required."
          });

      }


      if (!validTarget(target)) {

        return res
          .status(400)
          .json({
            error:
              "Target must be a valid HTTP or HTTPS URL."
          });

      }


      if (projectPath === "/") {

        return res
          .status(400)
          .json({
            error:
              "Path cannot be /."
          });

      }


      const exists =
        await Project.findOne({
          path: projectPath
        });


      if (exists) {

        return res
          .status(409)
          .json({
            error:
              "This path already exists."
          });

      }


      const project =
        await Project.create({

          name,

          path: projectPath,

          target:
            target.replace(/\/$/, ""),

          description:
            description || "",

          postUrl:
            postUrl || "",

          image:
            req.file
              ? "/uploads/" +
                req.file.filename
              : "",

          active: true

        });


      res.json(project);

    } catch (error) {

      console.error(error);

      res
        .status(500)
        .json({
          error: error.message
        });

    }

  }
);


// =====================================================
// ADMIN UPDATE PROJECT
// =====================================================

app.put(
  "/api/admin/projects/:id",
  adminOnly,
  upload.single("image"),

  async (req, res) => {

    try {

      const project =
        await Project.findById(
          req.params.id
        );


      if (!project) {

        return res
          .status(404)
          .json({
            error:
              "Project not found."
          });

      }


      const projectPath =
        cleanPath(req.body.path);


      if (!validTarget(req.body.target)) {

        return res
          .status(400)
          .json({
            error:
              "Invalid target URL."
          });

      }


      const duplicate =
        await Project.findOne({

          path: projectPath,

          _id: {
            $ne: project._id
          }

        });


      if (duplicate) {

        return res
          .status(409)
          .json({
            error:
              "This path already exists."
          });

      }


      project.name =
        req.body.name;

      project.path =
        projectPath;

      project.target =
        req.body.target.replace(
          /\/$/,
          ""
        );

      project.description =
        req.body.description || "";

      project.postUrl =
        req.body.postUrl || "";


      if (req.file) {

        project.image =
          "/uploads/" +
          req.file.filename;

      }


      if (
        req.body.active !==
        undefined
      ) {

        project.active =
          req.body.active ===
          "true";

      }


      await project.save();

      res.json(project);

    } catch (error) {

      console.error(error);

      res
        .status(500)
        .json({
          error:
            error.message
        });

    }

  }
);


// =====================================================
// ADMIN DELETE PROJECT
// =====================================================

app.delete(
  "/api/admin/projects/:id",
  adminOnly,

  async (req, res) => {

    try {

      const project =
        await Project.findByIdAndDelete(
          req.params.id
        );


      if (!project) {

        return res
          .status(404)
          .json({
            error:
              "Project not found."
          });

      }


      if (
        project.image &&
        project.image.startsWith(
          "/uploads/"
        )
      ) {

        const filePath =
          path.join(
            __dirname,
            "public",
            project.image
          );


        if (
          fs.existsSync(filePath)
        ) {

          fs.unlinkSync(
            filePath
          );

        }

      }


      res.json({
        ok: true
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });

    }

  }
);


// =====================================================
// DYNAMIC REVERSE PROXY
// =====================================================

app.use(
  async (req, res, next) => {

    try {

      /*
        API requests should not be proxied.
      */

      if (
        req.path.startsWith(
          "/api/"
        )
      ) {

        return next();

      }


      /*
        Ignore admin/public files.
      */

      if (
        req.path ===
        "/admin.html"
      ) {

        return next();

      }


      /*
        Get first URL section.

        /bot
        /bot/
        /bot/login

        all become /bot
      */

      const firstPart =
        "/" +
        (
          req.path
            .split("/")[1] ||
          ""
        );


      if (
        !firstPart ||
        firstPart === "/"
      ) {

        return next();

      }


      const project =
        await Project.findOne({

          path: firstPart,

          active: true

        }).lean();


      if (!project) {

        return next();

      }


      const target =
        project.target;


      console.log(
        `[PROXY] ${req.method} ${req.originalUrl} -> ${target}`
      );


      return createProxyMiddleware({

        target,

        changeOrigin: true,

        secure: true,

        ws: true,

        xfwd: true,

        followRedirects: true,

        cookieDomainRewrite: "",


        pathRewrite: function (
          incomingPath
        ) {

          let remainder =
            incomingPath.slice(
              firstPart.length
            );


          if (!remainder) {

            remainder = "/";

          }


          if (
            !remainder.startsWith("/")
          ) {

            remainder =
              "/" + remainder;

          }


          return remainder;

        },


        on: {

          proxyReq:
            function (proxyReq) {

              proxyReq.setHeader(
                "X-SILA-PROXY",
                "SILA-TECH"
              );

            },


          proxyRes:
            responseInterceptor(
              async (
                responseBuffer,
                proxyRes
              ) => {

                const contentType =
                  String(
                    proxyRes.headers[
                      "content-type"
                    ] || ""
                  );


                /*
                  Best-effort HTML
                  URL rewriting.
                */

                if (
                  contentType.includes(
                    "text/html"
                  )
                ) {

                  let body =
                    responseBuffer.toString(
                      "utf8"
                    );


                  const escapedTarget =
                    target.replace(
                      /[.*+?^${}()|[\]\\]/g,
                      "\\$&"
                    );


                  const frontendBase =
                    process.env.BASE_URL ||
                    "";


                  body =
                    body.replace(
                      new RegExp(
                        escapedTarget,
                        "g"
                      ),
                      frontendBase +
                      firstPart
                    );


                  return Buffer.from(
                    body
                  );

                }


                return responseBuffer;

              }
            )

        }

      })(req, res, next);

    } catch (error) {

      console.error(
        "Proxy error:",
        error
      );

      next();

    }

  }
);


// =====================================================
// MAIN WEBSITE
// =====================================================

app.get(
  "*",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );

  }
);


// =====================================================
// START
// =====================================================

async function start() {

  try {

    await mongoose.connect(
      process.env.MONGODB_URI
    );


    console.log(
      "MongoDB connected."
    );


    app.listen(
      PORT,
      () => {

        console.log(
          `SILA TECH running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "MongoDB connection failed:",
      error.message
    );

    process.exit(1);

  }

}


start();