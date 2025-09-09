// Types partagés entre frontend et backend

export interface User {
  id: string;
  username: string;
  email: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface Transfer {
  id: string;
  fileName: string;
  fileSize: number;
  fileMimeType: string;
  totalChunks: number;
  completedChunks: number;
  status: TransferStatus;
  encryptionKey: string;
  integrityHash: string;
  senderId: string;
  receiverId: string;
  createdAt: string;
  updatedAt: string;
}

export enum TransferStatus {
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
  PAUSED = 'PAUSED',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED'
}

export enum PeerStatus {
  ONLINE = 'ONLINE',
  OFFLINE = 'OFFLINE',
  BUSY = 'BUSY',
  AVAILABLE = 'AVAILABLE'
}

export enum CompressionMethod {
  NONE = 'NONE',
  GZIP = 'GZIP',
  BROTLI = 'BROTLI'
}

export interface PeerConnection {
  id: string;
  peerId: string;
  socketId?: string;
  status: PeerStatus;
  ipAddress?: string;
  isOnline: boolean;
  lastSeen: string;
  capabilities?: any;
  userId: string;
  createdAt: string;
  updatedAt: string;
}

export interface WebRTCSignal {
  type: 'offer' | 'answer' | 'ice-candidate';
  targetPeerId: string;
  signal: any;
}
