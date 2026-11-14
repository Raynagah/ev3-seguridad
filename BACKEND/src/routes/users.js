const express = require("express");
const bcrypt = require("bcryptjs");
const { pool } = require("../db");
const jwt = require("jsonwebtoken");
const validate = require("../middleware/validate");
const { createUserSchema, updateUserSchema } = require("../validations/users");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

if (!JWT_SECRET) {
  throw new Error("ERROR CRÍTICO DE SEGURIDAD: JWT_SECRET no está definido.");
}

function getUserFromAuthHeader(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  try {
    const token = auth.substring(7);
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.error(error);
    return null;
  }
}

async function checkIsAdmin(authUser) {
  if (authUser.empresaId) {
    const res = await pool.query(
      `SELECT eu.rol_id, r.nombre AS rol_nombre
       FROM empresa_usuarios eu
       LEFT JOIN roles r ON r.id = eu.rol_id
       WHERE eu.usuario_id = $1 AND eu.empresa_id = $2`,
      [authUser.usuarioId, authUser.empresaId]
    );
    if (res.rows.length === 0) return false;
    const { rol_id, rol_nombre } = res.rows[0];
    return (
      rol_id === 1 || rol_nombre === "admin" || rol_nombre === "administrador"
    );
  }

  const res = await pool.query(
    `SELECT r.nombre 
     FROM usuario_roles ur
     JOIN roles r ON r.id = ur.rol_id
     WHERE ur.usuario_id = $1`,
    [authUser.usuarioId]
  );
  const roles = res.rows.map((r) => r.nombre);
  return roles.includes("admin") || roles.includes("administrador");
}

router.post("/", validate(createUserSchema), async (req, res) => {
  const { nombre_usuario, contrasena_hash, correo, rol_id } = req.body;
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    const isAdmin = await checkIsAdmin(authUser);
    if (!isAdmin) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo los administradores pueden crear usuarios",
      });
    }

    // Hashear contraseña antes de insertar en BD (Mitiga DEF-001)
    const hashedPassword = await bcrypt.hash(contrasena_hash, SALT_ROUNDS);

    const result = await pool.query(
      "INSERT INTO usuarios (nombre_usuario, contrasena, correo) VALUES ($1, $2, $3) RETURNING id, nombre_usuario, correo, created_at",
      [nombre_usuario, hashedPassword, correo]
    );
    const newUser = result.rows[0];

    if (authUser.empresaId && rol_id) {
      await pool.query(
        "INSERT INTO empresa_usuarios (empresa_id, usuario_id, rol_id) VALUES ($1, $2, $3)",
        [authUser.empresaId, newUser.id, rol_id]
      );
    } else if (rol_id) {
      await pool.query(
        "INSERT INTO usuario_roles (usuario_id, rol_id) VALUES ($1, $2)",
        [newUser.id, rol_id]
      );
    }

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser?.usuarioId || null,
        `USUARIOS_CREAR: creó usuario ${nombre_usuario}${rol_id ? ` con rol ${rol_id}` : ""}`,
      ]
    );

    return res.status(201).json(newUser);
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al crear usuario",
      glosa: err.message || err.toString(),
    });
  }
});

router.get("/", async (req, res) => {
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    const isAdmin = await checkIsAdmin(authUser);
    if (!isAdmin) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo los administradores pueden listar todos los usuarios",
      });
    }

    const result = await pool.query(
      `SELECT u.id, u.nombre_usuario, u.correo, u.created_at 
       FROM usuarios u
       ORDER BY u.id DESC`
    );

    return res.json(result.rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al listar usuarios",
      glosa: err.message || err.toString(),
    });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    if (authUser.empresaId) {
      const result = await pool.query(
        `SELECT 
          u.id, 
          u.nombre_usuario, 
          u.correo, 
          u.created_at,
          eu.rol_id,
          r.nombre AS rol_nombre
        FROM usuarios u
        INNER JOIN empresa_usuarios eu ON eu.usuario_id = u.id AND eu.empresa_id = $2
        LEFT JOIN roles r ON r.id = eu.rol_id
        WHERE u.id = $1 AND eu.empresa_id = $2`,
        [req.params.id, authUser.empresaId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "No encontrado" });
      }

      const usuario = result.rows[0];

      if (usuario.rol_id === 1) {
        const adminCount = await pool.query(
          `SELECT COUNT(*) as count 
           FROM empresa_usuarios 
           WHERE empresa_id = $1 AND rol_id = 1`,
          [authUser.empresaId]
        );
        // Uso de Number.parseInt con base 10 (Mitiga INC-04 SonarQube)
        usuario.es_unico_administrador =
          Number.parseInt(adminCount.rows[0].count, 10) === 1;
      } else {
        usuario.es_unico_administrador = false;
      }

      return res.json(usuario);
    }

    const userRolesResult = await pool.query(
      `SELECT r.nombre 
       FROM usuario_roles ur
       JOIN roles r ON r.id = ur.rol_id
       WHERE ur.usuario_id = $1`,
      [authUser.usuarioId]
    );
    const userRoles = userRolesResult.rows.map((r) => r.nombre);
    const isAdminOrMedico =
      userRoles.includes("admin") || userRoles.includes("medico");
    const isPaciente = userRoles.includes("paciente") && !isAdminOrMedico;

    if (isPaciente && Number(authUser.usuarioId) !== Number(req.params.id)) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo puede ver sus propios datos",
      });
    }

    const result = await pool.query(
      `SELECT 
        u.id, 
        u.nombre_usuario, 
        u.correo, 
        u.created_at,
        ur.rol_id,
        r.nombre AS rol_nombre
      FROM usuarios u
      LEFT JOIN usuario_roles ur ON ur.usuario_id = u.id
      LEFT JOIN roles r ON r.id = ur.rol_id
      WHERE u.id = $1
      LIMIT 1`,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No encontrado" });
    }

    const usuario = result.rows[0];
    usuario.es_unico_administrador = false;

    return res.json(usuario);
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al obtener usuario",
      glosa: err.message || err.toString(),
    });
  }
});

router.put("/:id", validate(updateUserSchema), async (req, res) => {
  const { nombre_usuario, contrasena_hash, correo, rol_id } = req.body;
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    if (authUser.empresaId) {
      return await updateUsuarioEmpresa(req, res, authUser, {
        nombre_usuario,
        contrasena_hash,
        correo,
        rol_id,
      });
    }

    return await updateUsuarioSistemaMedico(req, res, authUser, {
      nombre_usuario,
      contrasena_hash,
      correo,
      rol_id,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al actualizar usuario",
      glosa: err.message || err.toString(),
    });
  }
});

async function updateUsuarioEmpresa(
  req,
  res,
  authUser,
  { nombre_usuario, contrasena_hash, correo, rol_id }
) {
  try {
    const authUserRoleResult = await pool.query(
      `SELECT eu.rol_id, r.nombre AS rol_nombre
       FROM empresa_usuarios eu
       LEFT JOIN roles r ON r.id = eu.rol_id
       WHERE eu.usuario_id = $1 AND eu.empresa_id = $2`,
      [authUser.usuarioId, authUser.empresaId]
    );

    if (authUserRoleResult.rows.length === 0) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "No tiene permisos para editar usuarios",
      });
    }

    const authRolId = authUserRoleResult.rows[0].rol_id;
    const authRolNombre = authUserRoleResult.rows[0].rol_nombre;
    const isAdmin =
      authRolId === 1 ||
      authRolNombre === "admin" ||
      authRolNombre === "administrador";

    if (!isAdmin) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo los administradores pueden editar usuarios",
      });
    }

    if (rol_id !== undefined) {
      if (
        authUser.usuarioId &&
        Number(authUser.usuarioId) === Number(req.params.id)
      ) {
        return res.status(400).json({
          error: "No se puede cambiar el rol",
          glosa: "No puedes cambiar tu propio rol",
        });
      }

      const usuarioActual = await pool.query(
        `SELECT eu.rol_id 
         FROM empresa_usuarios eu
         WHERE eu.usuario_id = $1 AND eu.empresa_id = $2`,
        [req.params.id, authUser.empresaId]
      );

      if (usuarioActual.rows.length > 0 && usuarioActual.rows[0].rol_id === 1) {
        const adminCount = await pool.query(
          `SELECT COUNT(*) as count 
           FROM empresa_usuarios 
           WHERE empresa_id = $1 AND rol_id = 1`,
          [authUser.empresaId]
        );

        // Uso de Number.parseInt con base 10 (Mitiga INC-04 SonarQube)
        if (
          Number.parseInt(adminCount.rows[0].count, 10) === 1 &&
          rol_id !== 1
        ) {
          return res.status(400).json({
            error: "No se puede cambiar el rol",
            glosa:
              "No se puede cambiar el rol del único administrador de la empresa",
          });
        }
      }
    }

    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;

    if (nombre_usuario !== undefined) {
      updateFields.push(`nombre_usuario=$${paramIndex++}`);
      updateValues.push(nombre_usuario);
    }
    if (contrasena_hash !== undefined) {
      const hashedPassword = await bcrypt.hash(contrasena_hash, SALT_ROUNDS);
      updateFields.push(`contrasena=$${paramIndex++}`);
      updateValues.push(hashedPassword);
    }
    if (correo !== undefined) {
      updateFields.push(`correo=$${paramIndex++}`);
      updateValues.push(correo);
    }

    if (updateFields.length > 0) {
      updateValues.push(req.params.id);
      const result = await pool.query(
        `UPDATE usuarios SET ${updateFields.join(
          ", "
        )} WHERE id=$${paramIndex} RETURNING id, nombre_usuario, correo, created_at`,
        updateValues
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "No encontrado" });
      }
    }

    if (rol_id !== undefined) {
      const empresaUsuarioResult = await pool.query(
        `SELECT id FROM empresa_usuarios WHERE usuario_id = $1 AND empresa_id = $2`,
        [req.params.id, authUser.empresaId]
      );

      if (empresaUsuarioResult.rows.length > 0) {
        await pool.query(
          `UPDATE empresa_usuarios SET rol_id = $1 WHERE usuario_id = $2 AND empresa_id = $3`,
          [rol_id, req.params.id, authUser.empresaId]
        );
      }
    }

    const usuarioResult = await pool.query(
      `SELECT 
        u.id, 
        u.nombre_usuario, 
        u.correo, 
        u.created_at,
        eu.rol_id,
        r.nombre AS rol_nombre
      FROM usuarios u
      LEFT JOIN empresa_usuarios eu ON eu.usuario_id = u.id AND eu.empresa_id = $2
      LEFT JOIN roles r ON r.id = eu.rol_id
      WHERE u.id = $1`,
      [req.params.id, authUser.empresaId]
    );

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser?.usuarioId || null,
        `USUARIOS_ACTUALIZAR: actualizó usuario ID ${req.params.id}${
          rol_id !== undefined ? ` y rol a ${rol_id}` : ""
        }`,
      ]
    );

    return res.json(usuarioResult.rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al actualizar usuario",
      glosa: err.message || err.toString(),
    });
  }
}

async function updateUsuarioSistemaMedico(
  req,
  res,
  authUser,
  { nombre_usuario, contrasena_hash, correo, rol_id }
) {
  try {
    const userRolesResult = await pool.query(
      `SELECT r.nombre 
       FROM usuario_roles ur
       JOIN roles r ON r.id = ur.rol_id
       WHERE ur.usuario_id = $1`,
      [authUser.usuarioId]
    );
    const userRoles = userRolesResult.rows.map((r) => r.nombre);
    const isAdmin =
      userRoles.includes("admin") || userRoles.includes("administrador");
    const isAdminOrMedico =
      userRoles.includes("admin") ||
      userRoles.includes("administrador") ||
      userRoles.includes("medico");
    const isPaciente = userRoles.includes("paciente") && !isAdminOrMedico;

    if (isPaciente) {
      if (Number(authUser.usuarioId) !== Number(req.params.id)) {
        return res.status(403).json({
          error: "No autorizado",
          glosa: "Solo puede actualizar sus propios datos",
        });
      }
      if (rol_id !== undefined) {
        return res.status(403).json({
          error: "No autorizado",
          glosa: "No puede cambiar su rol",
        });
      }
    }

    if (!isAdmin && Number(authUser.usuarioId) !== Number(req.params.id)) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo los administradores pueden editar otros usuarios",
      });
    }

    if (rol_id !== undefined && !isAdminOrMedico) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "No tiene permisos para cambiar roles",
      });
    }

    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;

    if (nombre_usuario !== undefined) {
      updateFields.push(`nombre_usuario=$${paramIndex++}`);
      updateValues.push(nombre_usuario);
    }
    if (contrasena_hash !== undefined) {
      const hashedPassword = await bcrypt.hash(contrasena_hash, SALT_ROUNDS);
      updateFields.push(`contrasena=$${paramIndex++}`);
      updateValues.push(hashedPassword);
    }
    if (correo !== undefined) {
      updateFields.push(`correo=$${paramIndex++}`);
      updateValues.push(correo);
    }

    if (updateFields.length > 0) {
      updateValues.push(req.params.id);
      const result = await pool.query(
        `UPDATE usuarios SET ${updateFields.join(
          ", "
        )} WHERE id=$${paramIndex} RETURNING id, nombre_usuario, correo, created_at`,
        updateValues
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: "No encontrado" });
      }
    }

    if (rol_id !== undefined && isAdminOrMedico) {
      await pool.query(`DELETE FROM usuario_roles WHERE usuario_id = $1`, [
        req.params.id,
      ]);
      await pool.query(
        `INSERT INTO usuario_roles (usuario_id, rol_id) VALUES ($1, $2)`,
        [req.params.id, rol_id]
      );
    }

    const usuarioResult = await pool.query(
      `SELECT 
        u.id, 
        u.nombre_usuario, 
        u.correo, 
        u.created_at,
        ur.rol_id,
        r.nombre AS rol_nombre
      FROM usuarios u
      LEFT JOIN usuario_roles ur ON ur.usuario_id = u.id
      LEFT JOIN roles r ON r.id = ur.rol_id
      WHERE u.id = $1
      LIMIT 1`,
      [req.params.id]
    );

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser?.usuarioId || null,
        `USUARIOS_ACTUALIZAR: actualizó usuario ID ${req.params.id}${
          rol_id !== undefined ? ` y rol a ${rol_id}` : ""
        }`,
      ]
    );

    return res.json(usuarioResult.rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al actualizar usuario",
      glosa: err.message || err.toString(),
    });
  }
}

router.delete("/:id", async (req, res) => {
  try {
    const authUser = getUserFromAuthHeader(req);
    if (!authUser) {
      return res.status(401).json({
        error: "No autorizado",
        glosa: "Token inválido",
      });
    }

    const isAdmin = await checkIsAdmin(authUser);
    if (!isAdmin) {
      return res.status(403).json({
        error: "No autorizado",
        glosa: "Solo los administradores pueden eliminar usuarios",
      });
    }

    const result = await pool.query(
      "DELETE FROM usuarios WHERE id=$1 RETURNING id",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No encontrado" });
    }

    await pool.query(
      "INSERT INTO auditoria (usuario_id, accion) VALUES ($1, $2)",
      [
        authUser.usuarioId,
        `USUARIOS_ELIMINAR: eliminó usuario ID ${req.params.id}`,
      ]
    );

    return res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Error al eliminar usuario",
      glosa: err.message || err.toString(),
    });
  }
});

module.exports = router;