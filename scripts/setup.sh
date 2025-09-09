#!/bin/bash
set -e

echo "🚀 Configuration du projet P2P File Transfer..."

# Créer les fichiers d'environnement
echo "📝 Création des fichiers d'environnement..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Fichier .env créé"
fi

if [ ! -f frontend/.env.local ]; then
    cp frontend/.env.local.example frontend/.env.local
    echo "✅ Fichier frontend/.env.local créé"
fi

if [ ! -f backend/.env ]; then
    cp .env.example backend/.env
    echo "✅ Fichier backend/.env créé"
fi

# Installer les dépendances
echo "📦 Installation des dépendances..."
npm install

echo "✅ Configuration terminée!"
echo ""
echo "📋 Prochaines étapes:"
echo "1. Configurer votre base de données dans .env"
echo "2. Lancer: npm run dev"
echo "3. Ouvrir: http://localhost:3000"
echo ""
echo "🔧 Pour une base de données locale avec Docker:"
echo "docker run --name p2p-postgres -e POSTGRES_PASSWORD=password -e POSTGRES_DB=p2p_file_transfer -p 5432:5432 -d postgres:15"
