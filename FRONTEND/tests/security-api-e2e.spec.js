import { test, expect } from '@playwright/test';

const BACKEND_URL = 'http://localhost:4444';

test.describe('Suite Automatizada de Seguridad API Backend - Cuidarte+', () => {

  // A5: Rechazo de acceso sin autenticación en rutas protegidas del Backend
  test('CP-ROL-01-API (Backend): Bloqueo HTTP 401/403 sin token JWT en /usuarios y /auditoria', async ({ request }) => {
    for (const endpoint of ['/usuarios', '/auditoria']) {
      const res = await request.get(`${BACKEND_URL}${endpoint}`);
      expect([401, 403]).toContain(res.status());
    }
  });

  // A5: Control de acceso basado en roles (RBAC) en Backend — Token de paciente vs ruta administrativa
  test('CP-ROL-02-API (Backend RBAC): Token con rol paciente recibe HTTP 401/403 al consultar /usuarios y /auditoria', async ({ request }) => {
    const loginRes = await request.post(`${BACKEND_URL}/autenticacion/login`, {
      data: {
        nombre_usuario: 'paciente',
        password: 'paciente',
      },
    });
    expect(loginRes.ok()).toBeTruthy();

    const loginBody = await loginRes.json();
    const pacienteToken = loginBody.token || loginBody.accessToken || loginBody.data?.token;
    expect(pacienteToken).toBeTruthy();

    for (const adminEndpoint of ['/usuarios', '/auditoria']) {
      const forbiddenRes = await request.get(`${BACKEND_URL}${adminEndpoint}`, {
        headers: { Authorization: `Bearer ${pacienteToken}` },
      });
      expect([401, 403]).toContain(forbiddenRes.status());
    }
  });

  // A3: Automatización CP-004 — Confidencialidad de contraseñas y formato hash bcrypt ($2b$)
  test('CP-004-API (Backend): La API no expone contraseñas en texto plano y valida formato bcrypt', async ({ request }) => {
    const loginRes = await request.post(`${BACKEND_URL}/autenticacion/login`, {
      data: {
        nombre_usuario: 'admin',
        password: 'admin',
      },
    });
    expect(loginRes.ok()).toBeTruthy();

    const loginBody = await loginRes.json();
    const adminToken = loginBody.token || loginBody.accessToken || loginBody.data?.token;

    // 1. La respuesta del login nunca debe devolver la contraseña en claro
    expect(JSON.stringify(loginBody)).not.toContain('"password":"admin"');

    // 2. Si el listado de usuarios incluye el campo password, debe estar cifrado con bcrypt ($2a$/$2b$)
    if (adminToken) {
      const usersRes = await request.get(`${BACKEND_URL}/usuarios`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      if (usersRes.ok()) {
        const usersPayload = await usersRes.json();
        const usersList = Array.isArray(usersPayload)
          ? usersPayload
          : usersPayload.usuarios || usersPayload.data || [];

        for (const usuario of usersList) {
          if (usuario.password !== undefined && usuario.password !== null) {
            expect(usuario.password).toMatch(/^\$2[aby]\$/);
            expect(usuario.password).not.toBe('admin');
          }
        }
      }
    }
  });
});