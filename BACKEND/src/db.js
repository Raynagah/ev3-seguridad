const { Pool } = require("pg");
require("dotenv").config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    "ERROR CRÍTICO DE SEGURIDAD: La variable de entorno DATABASE_URL no está definida."
  );
}

const pool = new Pool({ connectionString });

module.exports = { pool };