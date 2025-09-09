import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { PrismaClient } from '@prisma/client';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import dotenv from 'dotenv';

dotenv.config();

// Types de base
interface User {
  id: string;
  email: string;
  username: string;
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { userId: string };
    user: User;
  }
}

// Initialisation
const prisma = new PrismaClient();
const fastify = Fastify({
  logger: {
    level: 'info',
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true
      }
    }
  }
});

// Plugins
fastify.register(cors, {
  origin: [process.env.FRONTEND_URL || 'http://localhost:3000'],
  credentials: true
});

fastify.register(jwt, {
  secret: process.env.JWT_SECRET || 'fallback-secret'
});

// Routes de base
fastify.get('/health', async () => {
  return { 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: 'connected'
  };
});

// Route d'inscription
fastify.post<{
  Body: {
    username: string;
    email: string;
    password: string;
  }
}>('/api/auth/register', async (request, reply) => {
  const { username, email, password } = request.body;
  
  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username }
        ]
      }
    });

    if (existingUser) {
      return reply.status(400).send({
        error: 'User already exists'
      });
    }

    // Hash du mot de passe
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 12);

    // Créer l'utilisateur
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword
      }
    });

    // Générer le JWT
    const token = fastify.jwt.sign({ userId: user.id });

    return {
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },
      token
    };

  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({
      error: 'Internal server error'
    });
  }
});

// Route de connexion
fastify.post<{
  Body: {
    email: string;
    password: string;
  }
}>('/api/auth/login', async (request, reply) => {
  const { email, password } = request.body;

  try {
    // Trouver l'utilisateur
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return reply.status(401).send({
        error: 'Invalid credentials'
      });
    }

    // Vérifier le mot de passe
    const bcrypt = require('bcryptjs');
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return reply.status(401).send({
        error: 'Invalid credentials'
      });
    }

    // Générer le JWT
    const token = fastify.jwt.sign({ userId: user.id });

    return {
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },
      token
    };

  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({
      error: 'Internal server error'
    });
  }
});

// Configuration Socket.IO
const server = createServer();
const io = new SocketServer(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
});

// Stockage des connexions actives
const activePeers = new Map<string, {
  socketId: string;
  userId: string;
  username: string;
}>();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Authentification du socket
  socket.on('authenticate', async (token: string) => {
    try {
      const decoded = fastify.jwt.verify(token) as { userId: string };
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId }
      });

      if (user) {
        // Stocker la connexion
        activePeers.set(socket.id, {
          socketId: socket.id,
          userId: user.id,
          username: user.username
        });

        socket.join(`user-${user.id}`);
        
        // Notifier les autres peers
        socket.broadcast.emit('peer-online', {
          peerId: socket.id,
          username: user.username,
          userId: user.id
        });

        // Envoyer la liste des peers connectés
        const peers = Array.from(activePeers.values())
          .filter(peer => peer.socketId !== socket.id);
        
        socket.emit('peers-list', peers);

        console.log(`User authenticated: ${user.username}`);
      }
    } catch (error) {
      console.log('Authentication failed:', error);
      socket.disconnect();
    }
  });

  // Signaling pour WebRTC
  socket.on('webrtc-signal', (data: {
    targetPeerId: string;
    signal: any;
  }) => {
    socket.to(data.targetPeerId).emit('webrtc-signal', {
      fromPeerId: socket.id,
      signal: data.signal
    });
  });

  // Déconnexion
  socket.on('disconnect', () => {
    const peer = activePeers.get(socket.id);
    if (peer) {
      activePeers.delete(socket.id);
      socket.broadcast.emit('peer-offline', {
        peerId: socket.id,
        userId: peer.userId
      });
      console.log(`User disconnected: ${peer.username}`);
    }
  });
});

// Démarrage du serveur
async function start() {
  try {
    // Démarrer Fastify
    await fastify.listen({ 
      port: parseInt(process.env.PORT || '3001'),
      host: '0.0.0.0'
    });

    // Démarrer Socket.IO sur le port +1000
    const socketPort = parseInt(process.env.PORT || '3001') + 1000;
    server.listen(socketPort, () => {
      console.log(`Socket.IO server listening on port ${socketPort}`);
    });

    console.log('🚀 Backend servers started successfully');
    
  } catch (error) {
    fastify.log.error(error);
    process.exit(1);
  }
}

// Gestion de l'arrêt propre
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});

start();
