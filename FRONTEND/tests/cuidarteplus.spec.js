import { test, expect } from "@playwright/test";

test.describe("Suite Automatizada E2E y Normativa - Cuidarte+", () => {
  test("CP-001: Disponibilidad de interfaz y validación controlada de autenticación", async ({
    page,
  }) => {
    const response = await page.goto("/");
    expect(response.status()).toBe(200);

    // Verificar que redirige a /login y renderiza los campos de acceso
    await expect(page).toHaveURL(/\/login/);
    const userInput = page.locator('input[name="nombre_usuario"], input[type="text"]').first();
    const passInput = page.locator('input[name="password"], input[type="password"]').first();
    await expect(userInput).toBeVisible();
    await expect(passInput).toBeVisible();

    // Intentar acceso con credenciales inválidas y comprobar que mantiene el bloqueo en /login
    await userInput.fill("usuario_inexistente");
    await passInput.fill("clave_incorrecta");
    await page.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/\/login/);
  });

  test("CP-ROL-01 (Ley 20.584): Bloqueo de acceso no autorizado a rutas clínicas y auditoría", async ({
    page,
  }) => {
    // Verificar reserva de ficha clínica y registros ante usuarios sin sesión
    for (const rutaProtegida of ["/auditoria", "/examenes", "/pacientes"]) {
      await page.goto(rutaProtegida);
      await expect(page).toHaveURL(/\/login/);
    }
  });

  test("CS-INY-01 (OWASP A03): Neutralización de payload XSS en formulario de acceso", async ({
    page,
  }) => {
    let dialogTriggered = false;
    page.on("dialog", async (dialog) => {
      dialogTriggered = true;
      await dialog.dismiss();
    });

    await page.goto("/login");
    const xssPayload = "<script>alert('XSS')</script>";

    await page.locator('input[name="nombre_usuario"], input[type="text"]').first().fill(xssPayload);
    await page.locator('input[name="password"], input[type="password"]').first().fill("123456");
    await page.locator('button[type="submit"]').click();

    // Aserción de seguridad: el navegador no ejecuta scripts inyectados
    expect(dialogTriggered).toBe(false);
    await expect(page.locator("body")).toBeVisible();
  });
});