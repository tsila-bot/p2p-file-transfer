#!/bin/bash
set -e

echo "🚀 Démarrage en mode développement..."

# Vérifier que les dépendances sont installées
if [ ! -d "node_modules" ]; then
    echo "📦 Installation des dépendances..."
    npm install
fi

# Générer le client Prisma
echo "🔄 Génération du client Prisma..."
cd backend
npm run db:generate
cd ..

# Démarrer les serveurs
echo "🚀 Démarrage des serveurs..."
npm run dev
