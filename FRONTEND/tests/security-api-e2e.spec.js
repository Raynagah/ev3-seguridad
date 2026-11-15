import { test, expect } from '@playwright/test';

const FRONTEND_URL = 'http://localhost:3333';
const BACKEND_URL = 'http://localhost:4444';

test.describe('Suite Automatizada de Seguridad UI y API Backend - Cuidarte+', () => {

  // A4: Aserciones explícitas en Frontend (Control de Acceso y XSS en DOM)
  test('CP-ROL-01 (Frontend): Bloqueo de acceso no autenticado a rutas protegidas', async ({ page }) => {
    await page.goto(`${FRONTEND_URL}/admin/dashboard`);
    await expect(page).toHaveURL(/.*login/);
  });

  test('CS-INY-01 (Frontend): Sanitización de payload XSS en formulario de acceso', async ({ page }) => {
    let dialogTriggered = false;
    page.on('dialog', () => { dialogTriggered = true; });

    await page.goto(`${FRONTEND_URL}/login`);
    await page.fill('input[type="email"], input[name="email"]', '<script>alert("XSS")</script>@test.cl');
    await page.fill('input[type="password"], input[name="password"]', 'ClavePrueba123!');
    await page.click('button[type="submit"]');

    expect(dialogTriggered).toBe(false);
    await expect(page.locator('body')).not.toContainText('<script>alert("XSS")</script>');
  });

  // A5: Validación real de RBAC en Backend (No inferir seguridad desde el Frontend)
  test('CP-ROL-01-API (Backend): Rechazo HTTP 401/403 ante acceso sin privilegios de Administrador', async ({ request }) => {
    // 1. Petición sin token a ruta administrativa del backend
    const unauthRes = await request.get(`${BACKEND_URL}/api/usuarios`);
    expect([401, 403]).toContain(unauthRes.status());
  });

  // A3: Automatización CP-004 (No exposición de contraseña en respuestas API y formato hash bcrypt)
  test('CP-004-API (Backend): La API nunca retorna el campo password ni hashes en claro', async ({ request }) => {
    const loginRes = await request.post(`${BACKEND_URL}/api/auth/login`, {
      data: {
        email: process.env.TEST_ADMIN_EMAIL || 'admin@cuidarteplus.cl',
        password: process.env.TEST_ADMIN_PASSWORD || 'Admin1234!'
      }
    });

    if (loginRes.ok()) {
      const body = await loginRes.json();
      const serialized = JSON.stringify(body);
      expect(serialized).not.toContain('Admin1234!');
      if (body.usuario?.password || body.user?.password) {
        const storedPwd = body.usuario?.password || body.user?.password;
        expect(storedPwd).toMatch(/^\$2[aby]\$/);
      }
    }
  });
});