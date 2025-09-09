# 🚀 P2P File Transfer

Application de transfert de fichiers pair-à-pair sécurisée développée avec Next.js et Node.js.

## ✨ Fonctionnalités

- 🔄 **Transfert P2P Direct** : Connexions WebRTC directes entre pairs
- 🔒 **Sécurité** : Authentification JWT et sessions sécurisées
- 📁 **Interface Moderne** : Interface utilisateur intuitive avec React/Next.js
- ⚡ **Temps Réel** : Communication en temps réel via Socket.IO
- 🗄️ **Base de données** : PostgreSQL avec Prisma ORM

## 🏗️ Architecture

- **Frontend**: Next.js 14 + React + TypeScript + Tailwind CSS
- **Backend**: Node.js + Fastify + TypeScript + Socket.IO  
- **Base de données**: PostgreSQL + Prisma ORM
- **Types partagés**: Package TypeScript commun

## 🚀 Démarrage Rapide

### Prérequis

- Node.js 18+
- PostgreSQL (ou Docker pour une instance locale)
- Git

### Installation

1. **Cloner le projet**
   ```bash
   git clone <votre-repo>
   cd p2p-file-transfer
   ```

2. **Configuration automatique**
   ```bash
   ./scripts/setup.sh
   ```

3. **Configurer la base de données**
   
   Option A: Utiliser Docker
   ```bash
   docker run --name p2p-postgres \
     -e POSTGRES_PASSWORD=password \
     -e POSTGRES_DB=p2p_file_transfer \
     -p 5432:5432 -d postgres:15
   ```
   
   Option B: Modifier DATABASE_URL dans .env avec votre instance PostgreSQL

4. **Initialiser la base de données**
   ```bash
   cd backend
   npm run db:push
   npm run db:generate
   cd ..
   ```

5. **Démarrer le développement**
   ```bash
   npm run dev
   ```

6. **Ouvrir l'application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:3001

## 📚 Structure du Projet

```
p2p-file-transfer/
├── 📁 frontend/          # Application Next.js
│   ├── src/app/         # Pages et composants
│   └── src/lib/         # Utilitaires et hooks
├── 📁 backend/          # API Node.js
│   ├── src/            # Code source
│   └── prisma/         # Schema base de données
├── 📁 shared/          # Types TypeScript partagés
├── 📁 scripts/         # Scripts d'automatisation
└── 📁 docs/           # Documentation
```

## 🔧 Scripts Disponibles

- `npm run dev` - Mode développement complet
- `npm run build` - Build de production
- `npm run dev:frontend` - Frontend uniquement
- `npm run dev:backend` - Backend uniquement
- `./scripts/setup.sh` - Configuration initiale
- `./scripts/dev.sh` - Démarrage développement

## 🧪 Test de Fonctionnement

1. Ouvrir http://localhost:3000
2. Créer un compte utilisateur
3. Se connecter au dashboard
4. Ouvrir un second onglet en navigation privée
5. Créer un second compte
6. Vérifier que les deux utilisateurs se voient dans la liste des pairs

## 🛠️ Développement

### Backend
- API REST avec Fastify
- WebSocket avec Socket.IO pour le temps réel
- Base de données PostgreSQL avec Prisma
- Authentification JWT

### Frontend  
- Next.js 14 avec App Router
- Interface Tailwind CSS
- Gestion d'état avec React hooks
- Communication temps réel

### Prochaines Étapes
- [ ] Implémentation WebRTC pour connexions P2P
- [ ] Système de transfert de fichiers par chunks
- [ ] Chiffrement de bout en bout
- [ ] Interface de glisser-déposer
- [ ] Gestion de reprise de transfert

## 🤝 Contribution

Les contributions sont les bienvenues ! Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour plus de détails.

## 📄 License

MIT License - voir [LICENSE](LICENSE) pour plus de détails.
