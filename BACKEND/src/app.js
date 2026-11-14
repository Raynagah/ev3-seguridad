const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const swaggerUi = require("swagger-ui-express");

const { pool } = require("./db");

const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/users");
const pacientesRoutes = require("./routes/pacientes");
const examenesRoutes = require("./routes/examenes");
const documentosRoutes = require("./routes/documentos");
const tipoExamenRoutes = require("./routes/tipo-examen");
const auditRoutes = require("./routes/audit");
const rolesRoutes = require("./routes/roles");

const app = express();

// 1. Seguridad de cabeceras HTTP (Mitiga ZAP: CSP, Anti-Clickjacking, nosniff, X-Powered-By)
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        frameAncestors: ["'none'"],
      },
    },
    frameguard: { action: "deny" },
  })
);

// 2. Política CORS restrictiva mediante lista blanca (Mitiga INC-02 SonarQube)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:3333")
  .split(",")
  .map((origin) => origin.trim());

app.use(
  cors({
    origin: (origin, callback) => {
      // Permitir peticiones sin Origin (ej. herramientas internas/curl/Playwright) o incluidas en lista blanca
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Origen no permitido por la política CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(express.json());
app.use(morgan("dev"));

const uploadsDir = path.join(__dirname, "..", "uploads", "documentos");
fs.mkdirSync(uploadsDir, { recursive: true });

app.use("/autenticacion", authRoutes);
app.use("/usuarios", userRoutes);
app.use("/pacientes", pacientesRoutes);
app.use("/examenes", examenesRoutes);
app.use("/documentos", documentosRoutes);
app.use("/tipo-examen", tipoExamenRoutes);
app.use("/auditoria", auditRoutes);
app.use("/roles", rolesRoutes);

const openapi = require("./openapi.json");
app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapi));
app.get("/openapi.json", (req, res) => {
  res.json(openapi);
});

app.use("/files/documentos", express.static(uploadsDir));

app.get("/", (req, res) => {
  res.json({ name: "cuidarteplus", status: "ok" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`cuidarteplus API escuchando en puerto ${PORT}`);
});