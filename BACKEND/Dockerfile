FROM node:18-alpine

WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias de producción
RUN npm ci --only=production

# Copiar código de la aplicación
COPY src/ ./src/
COPY sql/ ./sql/

# Crear directorios necesarios y asignar propiedad al usuario sin privilegios 'node'
RUN mkdir -p uploads/contracts uploads/documentos && chown -R node:node /app

# Aplicar principio de menor privilegio (Mitiga INC-07 SonarQube)
USER node

# Exponer puerto
EXPOSE 4000

# Comando para iniciar la aplicación
CMD ["node", "src/app.js"]