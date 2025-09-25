# Étape de build
FROM node:18-alpine AS builder

# Installer les dépendances système nécessaires
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Copier les fichiers de configuration
COPY package.json ./
COPY tsconfig.json ./

# Utiliser npm install au lieu de npm ci (plus tolérant)
RUN npm install

# Copier le code source
COPY src ./src
COPY prisma ./prisma

# Générer le client Prisma
RUN npx prisma generate

# Compiler TypeScript
RUN npm run build

# Étape de production
FROM node:18-alpine AS production

# Installer les dépendances système nécessaires
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Créer l'utilisateur non-root en premier
RUN addgroup -g 1001 -S nodejs && \
    adduser -S backend -u 1001

# Copier package.json uniquement
COPY --from=builder --chown=backend:nodejs /app/package.json ./

# Installer les dépendances de production
RUN npm install --only=production

# Copier les fichiers compilés et Prisma
COPY --from=builder --chown=backend:nodejs /app/dist ./dist
COPY --from=builder --chown=backend:nodejs /app/prisma ./prisma

# Générer le client Prisma en production
RUN npx prisma generate

# Passer à l'utilisateur non-root
USER backend

# Exposer les ports
EXPOSE 3001 4001

# Commande de démarrage - CORRIGÉ pour utiliser server.js
CMD ["node", "dist/server.js"]