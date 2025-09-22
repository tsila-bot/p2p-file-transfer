"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { io, Socket } from "socket.io-client";
import {
  WebRTCManager,
  WebRTCPeer,
  SecureFileTransferData,
} from "../../lib/p2p/WebRTCManager";
import {
  CryptoService,
  FileFingerprint,
  EncryptedData,
} from "../../lib/crypto/CryptoService";

interface User {
  id: string;
  username: string;
  email: string;
}

interface Peer {
  socketId?: string;
  userId: string;
  username: string;
  peerId?: string;
}

interface FileTransfer {
  id: string;
  fileName: string;
  fileSize: number;
  progress: number;
  peerId: string;
  peerName: string;
  status: "pending" | "transferring" | "completed" | "failed";
  chunks: Map<number, ArrayBuffer>;
  totalChunks: number;
  fingerprint?: FileFingerprint;
  encryptedChunks?: EncryptedData[];
  isEncrypted?: boolean;
  verificationStatus?: "pending" | "verified" | "failed";
  chunkHashes?: Map<number, string>;
  integrityScore?: number;
  encryptionMode?: "AES-256-GCM" | "AES-256-CBC";
  securityLevel?: "low" | "medium" | "high" | "military";
  transferStartTime?: number;
  lastActivityTime?: number;
  errorLog?: string[];
}

interface SecurityAlert {
  id: string;
  level: "info" | "warning" | "critical";
  message: string;
  timestamp: number;
}

interface ConnectionSecurity {
  keyExchanged: boolean;
  lastKeyRotation: number;
  encryptionStrength: number;
  integrityChecks: number;
  securityScore: number;
}

interface TransferSecurity {
  chunkVerifications: number;
  integrityFailures: number;
  corruptionDetected: boolean;
  hashMismatches: number;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [socketStatus, setSocketStatus] = useState<
    "disconnected" | "connecting" | "connected"
  >("disconnected");
  const [debugInfo, setDebugInfo] = useState<string[]>([]);
  const [webrtcManager, setWebrtcManager] = useState<WebRTCManager | null>(
    null
  );
  const [webrtcPeers, setWebrtcPeers] = useState<WebRTCPeer[]>([]);
  const [activeTransfers, setActiveTransfers] = useState<
    Map<string, FileTransfer>
  >(new Map());
  const [dragOver, setDragOver] = useState(false);

  // États de sécurité avancée
  const [cryptoSupport, setCryptoSupport] = useState<{
    supported: boolean;
    features: string[];
    errors: string[];
    securityLevel?: "low" | "medium" | "high" | "military";
  } | null>(null);
  const [encryptionStatus, setEncryptionStatus] = useState<Map<string, number>>(
    new Map()
  );
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([]);
  const [connectionSecurity, setConnectionSecurity] = useState<
    Map<string, ConnectionSecurity>
  >(new Map());
  const [transferSecurity, setTransferSecurity] = useState<
    Map<string, TransferSecurity>
  >(new Map());

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fonctions utilitaires de sécurité
  const addSecurityAlert = (
    level: "info" | "warning" | "critical",
    message: string
  ) => {
    const alert: SecurityAlert = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      level,
      message,
      timestamp: Date.now(),
    };
    setSecurityAlerts((prev) => [alert, ...prev.slice(0, 19)]);
    addDebug(`[SECURITY ${level.toUpperCase()}] ${message}`);
  };

  const calculateSecurityLevel = (
    peer?: WebRTCPeer
  ): "low" | "medium" | "high" | "military" => {
    if (!peer?.encryptionKey) return "low";

    const connectionInfo = connectionSecurity.get(peer.id);
    if (!connectionInfo) return "medium";

    if (
      connectionInfo.securityScore >= 90 &&
      connectionInfo.integrityChecks > 10
    )
      return "military";
    if (connectionInfo.securityScore >= 75) return "high";
    if (connectionInfo.securityScore >= 50) return "medium";
    return "low";
  };

  const validateChunkIntegrity = async (
    chunk: EncryptedData,
    index: number,
    transferId: string
  ): Promise<boolean> => {
    try {
      const chunkData = new TextEncoder().encode(chunk.data + chunk.iv);
      const hashBuffer = await crypto.subtle.digest("SHA-256", chunkData);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      setActiveTransfers((prev) => {
        const newMap = new Map(prev);
        const transfer = newMap.get(transferId);
        if (transfer) {
          if (!transfer.chunkHashes) transfer.chunkHashes = new Map();
          transfer.chunkHashes.set(index, hashHex);
          newMap.set(transferId, transfer);
        }
        return newMap;
      });

      setTransferSecurity((prev) => {
        const newMap = new Map(prev);
        const current = newMap.get(transferId) || {
          chunkVerifications: 0,
          integrityFailures: 0,
          corruptionDetected: false,
          hashMismatches: 0,
        };
        current.chunkVerifications++;
        newMap.set(transferId, current);
        return newMap;
      });

      return true;
    } catch (error) {
      addSecurityAlert(
        "critical",
        `Chunk integrity validation failed for transfer ${transferId}, chunk ${index}`
      );

      setTransferSecurity((prev) => {
        const newMap = new Map(prev);
        const current = newMap.get(transferId) || {
          chunkVerifications: 0,
          integrityFailures: 0,
          corruptionDetected: false,
          hashMismatches: 0,
        };
        current.integrityFailures++;
        current.corruptionDetected = true;
        newMap.set(transferId, current);
        return newMap;
      });

      return false;
    }
  };

  const addDebug = (message: string) => {
    console.log(message);
    setDebugInfo((prev) => [
      `${new Date().toLocaleTimeString()}: ${message}`,
      ...prev.slice(0, 9),
    ]);
  };

  useEffect(() => {
    // Test du support cryptographique
    CryptoService.testCryptoSupport().then((support) => {
      let securityLevel: "low" | "medium" | "high" | "military" = "low";
      if (support.supported && support.features.length >= 4)
        securityLevel = "high";
      if (
        support.supported &&
        support.features.includes("AES-GCM") &&
        support.features.includes("SHA-256")
      )
        securityLevel = "military";

      setCryptoSupport({ ...support, securityLevel });

      if (support.supported) {
        addSecurityAlert(
          "info",
          `Cryptographic support enabled: ${securityLevel} security level`
        );
      } else {
        addSecurityAlert(
          "critical",
          "Cryptographic support unavailable - transfers will be unencrypted"
        );
      }
    });

    // Vérification de l'authentification
    const token = localStorage.getItem("token");
    const userData = localStorage.getItem("user");

    if (!token || !userData) {
      router.push("/auth/login");
      return;
    }

    const parsedUser = JSON.parse(userData);
    setUser(parsedUser);
    addDebug(`User loaded: ${parsedUser.username}`);

    // Initialisation WebRTC Manager
    const webrtc = new WebRTCManager("http://localhost:4001");
    setWebrtcManager(webrtc);
    webrtc.authenticate(token);

    // Configuration des callbacks WebRTC
    webrtc.onPeerConnect((peerId) => {
      addDebug(`WebRTC connected to peer: ${peerId}`);
      setWebrtcPeers(webrtc.getAllPeers());

      setConnectionSecurity((prev) => {
        const newMap = new Map(prev);
        newMap.set(peerId, {
          keyExchanged: false,
          lastKeyRotation: Date.now(),
          encryptionStrength: 256,
          integrityChecks: 0,
          securityScore: 70,
        });
        return newMap;
      });

      addSecurityAlert(
        "info",
        `P2P connection established with peer ${peerId}`
      );
    });

    webrtc.onPeerDisconnect((peerId) => {
      addDebug(`WebRTC disconnected from peer: ${peerId}`);
      setWebrtcPeers(webrtc.getAllPeers());
    });

    webrtc.onStatusChange((peerId, status) => {
      addDebug(`WebRTC peer ${peerId} status: ${status}`);
      setWebrtcPeers(webrtc.getAllPeers());
    });

    webrtc.onFileReceive((peerId, data) => {
      handleSecureFileReceive(peerId, data);
    });

    webrtc.onEncryptionProgressUpdate((transferId, progress) => {
      setEncryptionStatus((prev) => new Map(prev.set(transferId, progress)));
    });

    // Configuration Socket.IO
    const socketUrl = "http://localhost:4001";
    const newSocket = io(socketUrl, {
      transports: ["websocket", "polling"],
    });

    newSocket.on("connect", () => {
      addDebug(`Socket.IO connected: ${newSocket.id}`);
      setSocketStatus("connected");
      newSocket.emit("authenticate", token);
    });

    newSocket.on("disconnect", () => {
      addDebug("Socket.IO disconnected");
      setSocketStatus("disconnected");
    });

    newSocket.on("connect_error", (error) => {
      addDebug(`Socket.IO connection error: ${error.message}`);
      setSocketStatus("disconnected");
    });

    newSocket.on("peers-list", (peersList: any[]) => {
      addDebug(`Received peers list: ${peersList.length} peers`);
      const normalizedPeers = peersList
        .map((peer) => ({
          socketId: peer.socketId || peer.peerId,
          userId: peer.userId,
          username: peer.username,
          peerId: peer.peerId || peer.socketId,
        }))
        .filter((peer) => peer.userId && peer.username);
      setPeers(normalizedPeers);
      addDebug(`Normalized ${normalizedPeers.length} peers`);
    });

    newSocket.on("peer-online", (peer: any) => {
      addDebug(`Peer came online: ${peer.username}`);
      const normalizedPeer = {
        socketId: peer.socketId || peer.peerId,
        userId: peer.userId,
        username: peer.username,
        peerId: peer.peerId || peer.socketId,
      };

      if (normalizedPeer.userId && normalizedPeer.username) {
        setPeers((prev) => {
          const exists = prev.find((p) => p.userId === normalizedPeer.userId);
          if (exists) return prev;
          return [...prev, normalizedPeer];
        });
      }
    });

    newSocket.on("peer-offline", (data: any) => {
      addDebug(`Peer went offline: ${JSON.stringify(data)}`);
      setPeers((prev) =>
        prev.filter(
          (p) =>
            p.socketId !== data.peerId &&
            p.peerId !== data.peerId &&
            p.userId !== data.userId
        )
      );
    });

    setSocket(newSocket);

    return () => {
      addDebug("Cleaning up connections");
      webrtc.cleanup();
      newSocket.disconnect();
    };
  }, [router]);

  const handleSecureFileReceive = async (
    peerId: string,
    data: SecureFileTransferData
  ) => {
    addDebug(`Secure file data received from ${peerId}: ${data.type}`);

    switch (data.type) {
      case "file-offer":
        if (
          data.transferId &&
          data.fileName &&
          data.fileSize !== undefined &&
          data.totalChunks !== undefined
        ) {
          const transfer: FileTransfer = {
            id: data.transferId,
            fileName: data.fileName,
            fileSize: data.fileSize,
            progress: 0,
            peerId,
            peerName: webrtcManager?.getPeer(peerId)?.username || "Unknown",
            status: "pending",
            chunks: new Map(),
            totalChunks: data.totalChunks,
            fingerprint: data.fingerprint,
            encryptedChunks: [],
            isEncrypted: true,
            verificationStatus: "pending",
            chunkHashes: new Map(),
            integrityScore: 0,
            encryptionMode: "AES-256-GCM",
            securityLevel: calculateSecurityLevel(
              webrtcManager?.getPeer(peerId)
            ),
            transferStartTime: Date.now(),
            lastActivityTime: Date.now(),
            errorLog: [],
          };

          setActiveTransfers(
            (prev) => new Map(prev.set(data.transferId!, transfer))
          );
          addDebug(
            `Encrypted file offer received: ${data.fileName} (${data.fileSize} bytes)`
          );
        }
        break;

      case "file-chunk":
        if (
          data.transferId &&
          data.chunkIndex !== undefined &&
          data.data &&
          data.iv
        ) {
          setActiveTransfers((prev) => {
            const currentMap = new Map(prev);
            const transfer = currentMap.get(data.transferId!);

            if (
              transfer &&
              typeof data.data === "string" &&
              typeof data.iv === "string"
            ) {
              const encryptedChunk: EncryptedData = {
                data: data.data,
                iv: data.iv,
              };

              validateChunkIntegrity(
                encryptedChunk,
                data.chunkIndex!,
                data.transferId!
              ).then((isValid) => {
                if (!isValid) {
                  addSecurityAlert(
                    "critical",
                    `Chunk integrity validation failed for transfer ${data.transferId}, chunk ${data.chunkIndex}`
                  );
                  setActiveTransfers((prev) => {
                    const map = new Map(prev);
                    const t = map.get(data.transferId!);
                    if (t && t.errorLog) {
                      t.errorLog.push(
                        `Chunk ${data.chunkIndex} integrity failed`
                      );
                      t.integrityScore = Math.max(
                        0,
                        (t.integrityScore || 100) - 5
                      );
                      map.set(data.transferId!, t);
                    }
                    return map;
                  });
                } else {
                  setActiveTransfers((prev) => {
                    const map = new Map(prev);
                    const t = map.get(data.transferId!);
                    if (t) {
                      const validChunks =
                        t.encryptedChunks?.filter((c) => c).length || 0;
                      t.integrityScore = Math.round(
                        (validChunks / t.totalChunks) * 100
                      );
                      t.lastActivityTime = Date.now();
                      map.set(data.transferId!, t);
                    }
                    return map;
                  });
                }
              });

              if (!transfer.encryptedChunks) transfer.encryptedChunks = [];
              transfer.encryptedChunks[data.chunkIndex!] = encryptedChunk;
              transfer.progress = Math.round(
                (transfer.encryptedChunks.filter((c) => c).length /
                  transfer.totalChunks) *
                  100
              );
              transfer.status = "transferring";
              transfer.lastActivityTime = Date.now();

              const transferTime =
                Date.now() - (transfer.transferStartTime || Date.now());
              if (transferTime > 300000) {
                addSecurityAlert(
                  "warning",
                  `Transfer ${data.transferId} taking longer than expected`
                );
              }

              addDebug(
                `Encrypted chunk ${data.chunkIndex! + 1}/${
                  transfer.totalChunks
                } received (${transfer.progress}%) - Integrity: ${
                  transfer.integrityScore || 0
                }%`
              );
              currentMap.set(data.transferId!, { ...transfer });
            }
            return currentMap;
          });
        }
        break;

      case "file-complete":
        if (data.transferId) {
          setActiveTransfers((prev) => {
            const currentMap = new Map(prev);
            const transfer = currentMap.get(data.transferId!);

            if (
              transfer &&
              transfer.encryptedChunks &&
              transfer.fingerprint &&
              webrtcManager
            ) {
              const peer = webrtcManager.getPeer(peerId);
              if (peer?.encryptionKey) {
                addSecurityAlert(
                  "info",
                  `Starting secure decryption for ${transfer.fileName}`
                );

                const integrityScore = transfer.integrityScore || 0;
                if (integrityScore < 95) {
                  addSecurityAlert(
                    "warning",
                    `File ${transfer.fileName} has low integrity score: ${integrityScore}%`
                  );
                }

                const transferSec = transferSecurity.get(data.transferId!);
                if (transferSec?.corruptionDetected) {
                  addSecurityAlert(
                    "critical",
                    `Corruption detected in transfer ${data.transferId} - proceeding with caution`
                  );
                }

                CryptoService.decryptFile(
                  transfer.encryptedChunks,
                  peer.encryptionKey,
                  transfer.fingerprint,
                  (progress) => {
                    setActiveTransfers((prev) => {
                      const map = new Map(prev);
                      const t = map.get(data.transferId!);
                      if (t) {
                        t.progress = progress;
                        t.lastActivityTime = Date.now();
                        map.set(data.transferId!, t);
                      }
                      return map;
                    });
                  }
                )
                  .then(({ file, verified }) => {
                    const transferTime =
                      Date.now() - (transfer.transferStartTime || Date.now());

                    if (verified && integrityScore >= 95) {
                      const url = URL.createObjectURL(file);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = transfer.fileName;
                      a.style.display = "none";
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);

                      transfer.status = "completed";
                      transfer.progress = 100;
                      transfer.verificationStatus = "verified";

                      setConnectionSecurity((prev) => {
                        const newMap = new Map(prev);
                        const connSec = newMap.get(peerId);
                        if (connSec) {
                          connSec.integrityChecks++;
                          connSec.securityScore = Math.min(
                            100,
                            connSec.securityScore + 2
                          );
                          newMap.set(peerId, connSec);
                        }
                        return newMap;
                      });

                      addSecurityAlert(
                        "info",
                        `File ${
                          transfer.fileName
                        } successfully decrypted and verified in ${(
                          transferTime / 1000
                        ).toFixed(1)}s - Integrity: ${integrityScore}%`
                      );
                      addDebug(
                        `Encrypted file received, verified and downloaded: ${transfer.fileName} (Security Level: ${transfer.securityLevel})`
                      );
                    } else {
                      transfer.status = "failed";
                      transfer.verificationStatus = "failed";

                      if (!verified) {
                        addSecurityAlert(
                          "critical",
                          `File integrity verification FAILED for ${transfer.fileName} - file may be corrupted or tampered with`
                        );
                      }
                      if (integrityScore < 95) {
                        addSecurityAlert(
                          "critical",
                          `File ${transfer.fileName} failed integrity threshold (${integrityScore}% < 95%)`
                        );
                      }

                      setConnectionSecurity((prev) => {
                        const newMap = new Map(prev);
                        const connSec = newMap.get(peerId);
                        if (connSec) {
                          connSec.securityScore = Math.max(
                            0,
                            connSec.securityScore - 10
                          );
                          newMap.set(peerId, connSec);
                        }
                        return newMap;
                      });

                      addDebug(
                        `File integrity verification failed: ${transfer.fileName}`
                      );
                    }

                    setActiveTransfers(
                      (prev) =>
                        new Map(prev.set(data.transferId!, { ...transfer }))
                    );
                  })
                  .catch((error) => {
                    addSecurityAlert(
                      "critical",
                      `Decryption error for ${transfer.fileName}: ${error}`
                    );
                    transfer.status = "failed";
                    transfer.verificationStatus = "failed";
                    if (transfer.errorLog) {
                      transfer.errorLog.push(`Decryption failed: ${error}`);
                    }

                    setConnectionSecurity((prev) => {
                      const newMap = new Map(prev);
                      const connSec = newMap.get(peerId);
                      if (connSec) {
                        connSec.securityScore = Math.max(
                          0,
                          connSec.securityScore - 20
                        );
                        newMap.set(peerId, connSec);
                      }
                      return newMap;
                    });

                    addDebug(`Error decrypting file: ${error}`);
                    setActiveTransfers(
                      (prev) =>
                        new Map(prev.set(data.transferId!, { ...transfer }))
                    );
                  });
              } else {
                transfer.status = "failed";
                addSecurityAlert(
                  "critical",
                  "No encryption key available for decryption - potential security breach"
                );
                addDebug("No encryption key available for decryption");
                currentMap.set(data.transferId!, { ...transfer });
              }
            }
            return currentMap;
          });
        }
        break;
    }
  };

  const handleConnectToPeer = async (peer: Peer) => {
    if (!webrtcManager || !peer.socketId) return;

    addDebug(`Connecting to peer: ${peer.username}`);
    const success = await webrtcManager.connectToPeer(
      peer.socketId,
      peer.username
    );

    if (success) {
      addDebug(`Connection initiated with ${peer.username}`);
    } else {
      addDebug(`Failed to connect to ${peer.username}`);
    }
  };

  const handleSendFile = async (file: File, peerId: string) => {
    if (!webrtcManager || !cryptoSupport?.supported) {
      addDebug(
        `Cannot send file: ${
          !webrtcManager ? "WebRTC not ready" : "Crypto not supported"
        }`
      );
      return;
    }

    const peer = webrtcManager.getPeer(peerId);
    if (!peer?.encryptionKey) {
      addDebug(
        `Cannot send file: No encryption key available for peer ${peerId}`
      );
      return;
    }

    addDebug(`Sending encrypted file ${file.name} to peer ${peerId}`);
    const success = await webrtcManager.sendFile(peerId, file);

    if (success) {
      addDebug(`Encrypted file ${file.name} sent successfully`);
    } else {
      addDebug(`Failed to send encrypted file ${file.name}`);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);

    const files = Array.from(e.dataTransfer.files);
    if (
      files.length > 0 &&
      webrtcPeers.length > 0 &&
      cryptoSupport?.supported
    ) {
      const connectedPeer = webrtcPeers.find((p) => p.status === "connected");
      if (connectedPeer) {
        files.forEach((file) => handleSendFile(file, connectedPeer.id));
      } else {
        addDebug("No connected peers available for file transfer");
      }
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (
      files &&
      files.length > 0 &&
      webrtcPeers.length > 0 &&
      cryptoSupport?.supported
    ) {
      const connectedPeer = webrtcPeers.find((p) => p.status === "connected");
      if (connectedPeer) {
        Array.from(files).forEach((file) =>
          handleSendFile(file, connectedPeer.id)
        );
      } else {
        addDebug("No connected peers available for file transfer");
      }
    }
  };

  const handleLogout = () => {
    if (socket) socket.disconnect();
    if (webrtcManager) webrtcManager.cleanup();
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    router.push("/");
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Chargement...</p>
        </div>
      </div>
    );
  }

  const connectedWebRTCPeers = webrtcPeers.filter(
    (p) => p.status === "connected"
  );
  const hasConnectedPeers = connectedWebRTCPeers.length > 0;
  const cryptoReady = cryptoSupport?.supported;
  const encryptedPeersCount = connectedWebRTCPeers.filter(
    (p) => webrtcManager?.getPeer(p.id)?.encryptionKey
  ).length;
  const highSecurityPeersCount = connectedWebRTCPeers.filter(
    (p) => calculateSecurityLevel(webrtcManager?.getPeer(p.id)) === "military"
  ).length;

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold">
                P2P File Transfer Sécurisé
              </h1>
              <div className="ml-4 flex items-center space-x-2">
                <div
                  className={`w-3 h-3 rounded-full ${
                    socketStatus === "connected"
                      ? "bg-green-400"
                      : socketStatus === "connecting"
                      ? "bg-yellow-400"
                      : "bg-red-400"
                  }`}
                ></div>
                <span className="text-sm text-gray-600">
                  Socket: {socketStatus}
                </span>
                <div
                  className={`w-3 h-3 rounded-full ${
                    connectedWebRTCPeers.length > 0
                      ? "bg-green-400"
                      : "bg-gray-400"
                  }`}
                ></div>
                <span className="text-sm text-gray-600">
                  P2P: {connectedWebRTCPeers.length} connected
                </span>
                <div
                  className={`w-3 h-3 rounded-full ${
                    cryptoSupport?.supported ? "bg-green-400" : "bg-red-400"
                  }`}
                ></div>
                <span className="text-sm text-gray-600">
                  Crypto: {cryptoSupport?.supported ? "OK" : "KO"}
                </span>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Bonjour, {user.username}</span>
              <button
                onClick={handleLogout}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Zone de drop sécurisée */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4 flex items-center">
                  {cryptoReady && hasConnectedPeers && (
                    <svg
                      className="w-5 h-5 mr-2 text-green-600"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                      />
                    </svg>
                  )}
                  Envoi Sécurisé
                  {hasConnectedPeers && (
                    <span className="text-sm text-gray-500 ml-2">
                      ({connectedWebRTCPeers.length} pair
                      {connectedWebRTCPeers.length > 1 ? "s" : ""} connecté
                      {connectedWebRTCPeers.length > 1 ? "s" : ""})
                    </span>
                  )}
                </h3>

                <div
                  className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors cursor-pointer ${
                    dragOver
                      ? "border-blue-500 bg-blue-50"
                      : hasConnectedPeers && cryptoReady
                      ? "border-green-300 bg-green-50 hover:border-green-400"
                      : "border-gray-300"
                  }`}
                  onDrop={handleDrop}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onClick={() =>
                    hasConnectedPeers &&
                    cryptoReady &&
                    fileInputRef.current?.click()
                  }
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-center">
                      <svg
                        className={`h-12 w-12 mr-2 ${
                          hasConnectedPeers && cryptoReady
                            ? "text-green-400"
                            : "text-gray-400"
                        }`}
                        stroke="currentColor"
                        fill="none"
                        viewBox="0 0 48 48"
                      >
                        <path
                          d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02"
                          strokeWidth={2}
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                      {cryptoReady && hasConnectedPeers && (
                        <svg
                          className="h-8 w-8 text-green-500"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                          />
                        </svg>
                      )}
                    </div>

                    {hasConnectedPeers && cryptoReady ? (
                      <div>
                        <p className="text-green-600 font-medium">
                          Glissez-déposez vos fichiers ici ou cliquez pour
                          sélectionner
                        </p>
                        <p className="text-xs text-green-600">
                          Transfert P2P direct avec chiffrement AES-256-GCM +
                          vérification SHA-256
                        </p>
                      </div>
                    ) : !cryptoReady ? (
                      <div>
                        <p className="text-red-600">
                          Fonctionnalités de sécurité non disponibles
                        </p>
                        <p className="text-xs text-gray-500">
                          Votre navigateur ne supporte pas les API
                          cryptographiques requises
                        </p>
                      </div>
                    ) : (
                      <div>
                        <p className="text-gray-600">
                          Connectez-vous d'abord à un pair pour envoyer des
                          fichiers
                        </p>
                        <p className="text-xs text-gray-500">
                          Utilisez le bouton "Connecter" dans la liste des pairs
                        </p>
                      </div>
                    )}
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    onChange={handleFileSelect}
                    className="hidden"
                    disabled={!hasConnectedPeers || !cryptoReady}
                  />
                </div>

                <div className="mt-4 flex items-center justify-center space-x-6 text-xs text-gray-500">
                  <div
                    className={`flex items-center ${
                      cryptoReady ? "text-green-600" : "text-red-600"
                    }`}
                  >
                    {cryptoReady ? "🔒" : "❌"} Chiffrement
                  </div>
                  <div
                    className={`flex items-center ${
                      cryptoReady ? "text-green-600" : "text-red-600"
                    }`}
                  >
                    {cryptoReady ? "🛡️" : "❌"} Intégrité
                  </div>
                  <div
                    className={`flex items-center ${
                      hasConnectedPeers ? "text-green-600" : "text-gray-500"
                    }`}
                  >
                    {hasConnectedPeers ? "🔗" : "⚫"} P2P Direct
                  </div>
                </div>
              </div>
            </div>

            {/* Liste des pairs connectés */}
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                  Pairs disponibles ({peers.length})
                </h3>
                <div className="space-y-3">
                  {peers.length === 0 ? (
                    <div className="text-center py-8">
                      <div className="text-gray-400 mb-2">
                        <svg
                          className="mx-auto h-12 w-12"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={1}
                            d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                          />
                        </svg>
                      </div>
                      <p className="text-gray-500">
                        Aucun autre pair connecté pour le moment
                      </p>
                      <p className="text-xs text-gray-400 mt-2">
                        Ouvrez un nouvel onglet et créez un autre compte pour
                        tester
                      </p>
                    </div>
                  ) : (
                    peers.map((peer, index) => {
                      const webrtcPeer = webrtcManager?.getPeer(
                        peer.socketId || ""
                      );
                      const isConnected = webrtcPeer?.status === "connected";
                      const isConnecting = webrtcPeer?.status === "connecting";
                      const hasEncryption = webrtcPeer?.encryptionKey
                        ? true
                        : false;

                      return (
                        <div
                          key={peer.userId || peer.socketId || index}
                          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                        >
                          <div className="flex items-center">
                            <div
                              className={`w-3 h-3 rounded-full mr-3 ${
                                isConnected
                                  ? "bg-green-400"
                                  : isConnecting
                                  ? "bg-yellow-400"
                                  : "bg-gray-400"
                              }`}
                            ></div>
                            <div>
                              <span className="font-medium text-gray-900 flex items-center">
                                {peer.username || "Utilisateur inconnu"}
                                {isConnected && hasEncryption && (
                                  <svg
                                    className="w-4 h-4 ml-1 text-green-600"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                  >
                                    <path
                                      strokeLinecap="round"
                                      strokeLinejoin="round"
                                      strokeWidth={2}
                                      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                                    />
                                  </svg>
                                )}
                              </span>
                              <p className="text-xs text-gray-500">
                                {isConnected
                                  ? hasEncryption
                                    ? "P2P Connecté + Chiffré"
                                    : "P2P Connecté (clé en attente)"
                                  : isConnecting
                                  ? "Connexion..."
                                  : `ID: ${
                                      peer.socketId?.substring(0, 8) ||
                                      peer.userId?.substring(0, 8) ||
                                      "unknown"
                                    }...`}
                              </p>
                            </div>
                          </div>
                          <button
                            onClick={() => handleConnectToPeer(peer)}
                            disabled={isConnected || isConnecting}
                            className={`px-3 py-1 rounded text-sm font-medium ${
                              isConnected
                                ? "bg-green-100 text-green-700 cursor-default"
                                : isConnecting
                                ? "bg-yellow-100 text-yellow-700 cursor-wait"
                                : "bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                            }`}
                          >
                            {isConnected
                              ? "Connecté"
                              : isConnecting
                              ? "Connexion..."
                              : "Connecter"}
                          </button>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Alertes de sécurité */}
          {securityAlerts.length > 0 && (
            <div className="mt-6 bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4 flex items-center">
                  <svg
                    className="w-5 h-5 mr-2 text-yellow-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                    />
                  </svg>
                  Alertes de Sécurité ({securityAlerts.length})
                </h3>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {securityAlerts.slice(0, 10).map((alert) => (
                    <div
                      key={alert.id}
                      className={`p-3 rounded-md border-l-4 ${
                        alert.level === "critical"
                          ? "bg-red-50 border-red-400"
                          : alert.level === "warning"
                          ? "bg-yellow-50 border-yellow-400"
                          : "bg-blue-50 border-blue-400"
                      }`}
                    >
                      <div className="flex">
                        <div className="flex-shrink-0">
                          {alert.level === "critical" && (
                            <svg
                              className="h-4 w-4 text-red-400"
                              fill="currentColor"
                              viewBox="0 0 20 20"
                            >
                              <path
                                fillRule="evenodd"
                                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                                clipRule="evenodd"
                              />
                            </svg>
                          )}
                          {alert.level === "warning" && (
                            <svg
                              className="h-4 w-4 text-yellow-400"
                              fill="currentColor"
                              viewBox="0 0 20 20"
                            >
                              <path
                                fillRule="evenodd"
                                d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                                clipRule="evenodd"
                              />
                            </svg>
                          )}
                          {alert.level === "info" && (
                            <svg
                              className="h-4 w-4 text-blue-400"
                              fill="currentColor"
                              viewBox="0 0 20 20"
                            >
                              <path
                                fillRule="evenodd"
                                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                                clipRule="evenodd"
                              />
                            </svg>
                          )}
                        </div>
                        <div className="ml-3 flex-1">
                          <p
                            className={`text-sm ${
                              alert.level === "critical"
                                ? "text-red-700"
                                : alert.level === "warning"
                                ? "text-yellow-700"
                                : "text-blue-700"
                            }`}
                          >
                            {alert.message}
                          </p>
                          <p className="text-xs text-gray-500 mt-1">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Transferts sécurisés */}
          {activeTransfers.size > 0 && (
            <div className="mt-6 bg-white overflow-hidden shadow rounded-lg">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4 flex items-center">
                  <svg
                    className="w-5 h-5 mr-2 text-blue-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                    />
                  </svg>
                  Transferts Sécurisés ({activeTransfers.size})
                </h3>
                <div className="space-y-3">
                  {Array.from(activeTransfers.values()).map((transfer) => {
                    const encryptionProgress =
                      encryptionStatus.get(transfer.id) || 0;
                    const transferSec = transferSecurity.get(transfer.id);
                    const integrityScore = transfer.integrityScore || 0;
                    const securityLevel = transfer.securityLevel || "medium";

                    return (
                      <div
                        key={transfer.id}
                        className={`border rounded-lg p-4 ${
                          securityLevel === "military"
                            ? "bg-green-50 border-green-200"
                            : securityLevel === "high"
                            ? "bg-blue-50 border-blue-200"
                            : securityLevel === "medium"
                            ? "bg-yellow-50 border-yellow-200"
                            : "bg-red-50 border-red-200"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center">
                            <div className="flex items-center mr-2">
                              <svg
                                className={`w-4 h-4 mr-1 ${
                                  securityLevel === "military"
                                    ? "text-green-600"
                                    : securityLevel === "high"
                                    ? "text-blue-600"
                                    : securityLevel === "medium"
                                    ? "text-yellow-600"
                                    : "text-red-600"
                                }`}
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                                />
                              </svg>
                              <span
                                className={`text-xs font-medium ${
                                  securityLevel === "military"
                                    ? "text-green-600"
                                    : securityLevel === "high"
                                    ? "text-blue-600"
                                    : securityLevel === "medium"
                                    ? "text-yellow-600"
                                    : "text-red-600"
                                }`}
                              >
                                {securityLevel.toUpperCase()}
                              </span>
                            </div>
                            <div>
                              <p className="font-medium text-gray-900">
                                {transfer.fileName}
                              </p>
                              <p className="text-sm text-gray-500">
                                de {transfer.peerName} •{" "}
                                {(transfer.fileSize / 1024 / 1024).toFixed(1)}{" "}
                                MB • {transfer.encryptionMode}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            {transfer.verificationStatus === "verified" && (
                              <svg
                                className="w-4 h-4 text-green-600"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                              >
                                <path
                                  strokeLinecap="round"
                                  strokeLinejoin="round"
                                  strokeWidth={2}
                                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                                />
                              </svg>
                            )}
                            <div
                              className={`px-2 py-1 rounded text-xs font-medium ${
                                transfer.status === "completed"
                                  ? "bg-green-100 text-green-700"
                                  : transfer.status === "transferring"
                                  ? "bg-blue-100 text-blue-700"
                                  : transfer.status === "failed"
                                  ? "bg-red-100 text-red-700"
                                  : "bg-gray-100 text-gray-700"
                              }`}
                            >
                              {transfer.status}
                            </div>
                          </div>
                        </div>

                        <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                          <div
                            className={`h-2 rounded-full transition-all duration-300 ${
                              transfer.status === "completed"
                                ? "bg-green-500"
                                : transfer.status === "failed"
                                ? "bg-red-500"
                                : "bg-blue-500"
                            }`}
                            style={{
                              width: `${Math.max(
                                transfer.progress,
                                encryptionProgress
                              )}%`,
                            }}
                          ></div>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-600 mb-2">
                          <div>
                            <span className="font-medium">Progression:</span>{" "}
                            {Math.round(
                              Math.max(transfer.progress, encryptionProgress)
                            )}
                            %
                            {encryptionProgress > 0 &&
                              transfer.progress === 0 &&
                              " (chiffrement)"}
                          </div>
                          <div>
                            <span className="font-medium">Intégrité:</span>
                            <span
                              className={`ml-1 ${
                                integrityScore >= 95
                                  ? "text-green-600"
                                  : integrityScore >= 80
                                  ? "text-yellow-600"
                                  : "text-red-600"
                              }`}
                            >
                              {integrityScore}%
                            </span>
                          </div>
                          <div>
                            <span className="font-medium">Chunks:</span>{" "}
                            {transfer.encryptedChunks?.filter((c) => c)
                              .length || 0}
                            /{transfer.totalChunks}
                          </div>
                          <div>
                            <span className="font-medium">Hashs:</span>{" "}
                            {transfer.chunkHashes?.size || 0}
                          </div>
                        </div>

                        {transferSec && (
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-500">
                            <div>
                              <span className="font-medium">
                                Vérifications:
                              </span>{" "}
                              {transferSec.chunkVerifications}
                            </div>
                            <div>
                              <span className="font-medium">Échecs:</span>
                              <span
                                className={
                                  transferSec.integrityFailures > 0
                                    ? "text-red-600 ml-1"
                                    : "ml-1"
                                }
                              >
                                {transferSec.integrityFailures}
                              </span>
                            </div>
                            <div>
                              <span className="font-medium">Hash Erreurs:</span>
                              <span
                                className={
                                  transferSec.hashMismatches > 0
                                    ? "text-red-600 ml-1"
                                    : "ml-1"
                                }
                              >
                                {transferSec.hashMismatches}
                              </span>
                            </div>
                            <div>
                              <span className="font-medium">Corruption:</span>
                              <span
                                className={
                                  transferSec.corruptionDetected
                                    ? "text-red-600 ml-1"
                                    : "text-green-600 ml-1"
                                }
                              >
                                {transferSec.corruptionDetected ? "Oui" : "Non"}
                              </span>
                            </div>
                          </div>
                        )}

                        {transfer.errorLog && transfer.errorLog.length > 0 && (
                          <div className="mt-2 p-2 bg-red-100 rounded text-xs">
                            <span className="font-medium text-red-800">
                              Erreurs:
                            </span>
                            <ul className="mt-1 text-red-700">
                              {transfer.errorLog
                                .slice(-3)
                                .map((error, index) => (
                                  <li key={index}>• {error}</li>
                                ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Section de sécurité */}
          <div className="mt-6 bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4 flex items-center">
                <svg
                  className="w-5 h-5 mr-2 text-green-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
                Sécurité et Chiffrement
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                <div className="text-center">
                  <div
                    className={`text-2xl font-bold ${
                      cryptoSupport?.supported
                        ? "text-green-600"
                        : "text-red-600"
                    }`}
                  >
                    {cryptoSupport?.supported ? "🔒" : "❌"}
                  </div>
                  <div className="text-gray-500">Crypto Support</div>
                  <div className="text-xs text-gray-400">
                    {cryptoSupport?.securityLevel || "unknown"}
                  </div>
                </div>

                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    AES-256-GCM
                  </div>
                  <div className="text-gray-500">Chiffrement</div>
                  <div className="text-xs text-gray-400">Mode authentifié</div>
                </div>

                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    SHA-256
                  </div>
                  <div className="text-gray-500">Intégrité</div>
                  <div className="text-xs text-gray-400">
                    Par chunk + global
                  </div>
                </div>

                <div className="text-center">
                  <div
                    className={`text-2xl font-bold ${
                      highSecurityPeersCount > 0
                        ? "text-green-600"
                        : encryptedPeersCount > 0
                        ? "text-yellow-600"
                        : "text-gray-600"
                    }`}
                  >
                    {highSecurityPeersCount > 0
                      ? "🛡️"
                      : encryptedPeersCount > 0
                      ? "🔐"
                      : "⚫"}
                  </div>
                  <div className="text-gray-500">Sécurité Niveau</div>
                  <div className="text-xs text-gray-400">
                    {highSecurityPeersCount} militaire / {encryptedPeersCount}{" "}
                    chiffrés
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="p-3 bg-gray-100 rounded text-xs">
                  <h4 className="font-semibold mb-2">Métriques de Sécurité</h4>
                  <div className="space-y-1">
                    <p>
                      <strong>Alertes critiques:</strong>{" "}
                      {
                        securityAlerts.filter((a) => a.level === "critical")
                          .length
                      }
                    </p>
                    <p>
                      <strong>Alertes total:</strong> {securityAlerts.length}
                    </p>
                    <p>
                      <strong>Transferts sécurisés:</strong>{" "}
                      {
                        Array.from(activeTransfers.values()).filter(
                          (t) => t.isEncrypted
                        ).length
                      }
                    </p>
                    <p>
                      <strong>Score intégrité moyen:</strong>{" "}
                      {Array.from(activeTransfers.values()).length > 0
                        ? Math.round(
                            Array.from(activeTransfers.values()).reduce(
                              (acc, t) => acc + (t.integrityScore || 0),
                              0
                            ) / Array.from(activeTransfers.values()).length
                          )
                        : 0}
                      %
                    </p>
                  </div>
                </div>

                <div className="p-3 bg-gray-100 rounded text-xs">
                  <h4 className="font-semibold mb-2">Surveillance Réseau</h4>
                  <div className="space-y-1">
                    {Array.from(connectionSecurity.entries())
                      .slice(0, 3)
                      .map(([peerId, sec]) => {
                        const peer = webrtcManager?.getPeer(peerId);
                        return (
                          <div key={peerId} className="flex justify-between">
                            <span>{peer?.username || peerId.slice(0, 6)}:</span>
                            <span
                              className={`font-medium ${
                                sec.securityScore >= 80
                                  ? "text-green-600"
                                  : sec.securityScore >= 60
                                  ? "text-yellow-600"
                                  : "text-red-600"
                              }`}
                            >
                              {sec.securityScore}/100
                            </span>
                          </div>
                        );
                      })}
                    {connectionSecurity.size === 0 && (
                      <p className="text-gray-500">
                        Aucune connexion sécurisée active
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {cryptoSupport && (
                <div className="p-3 bg-gray-100 rounded text-xs">
                  <h4 className="font-semibold mb-2">
                    Fonctionnalités cryptographiques
                  </h4>
                  {cryptoSupport.supported ? (
                    <div>
                      <p className="text-green-600 mb-1">
                        ✅ Toutes les fonctions de sécurité sont disponibles
                      </p>
                      <p>
                        <strong>Supporté:</strong>{" "}
                        {cryptoSupport.features.join(", ")}
                      </p>
                    </div>
                  ) : (
                    <div>
                      <p className="text-red-600 mb-1">
                        ❌ Support cryptographique limité
                      </p>
                      <p>
                        <strong>Erreurs:</strong>{" "}
                        {cryptoSupport.errors.join(", ")}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Statistiques et Debug */}
          <div className="mt-6 bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                Statistiques & Debug
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-7 gap-4 mb-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {peers.length}
                  </div>
                  <div className="text-gray-500">Pairs découverts</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {connectedWebRTCPeers.length}
                  </div>
                  <div className="text-gray-500">Connexions P2P</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {encryptedPeersCount}
                  </div>
                  <div className="text-gray-500">Pairs chiffrés</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-emerald-600">
                    {highSecurityPeersCount}
                  </div>
                  <div className="text-gray-500">Niveau militaire</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-600">
                    {activeTransfers.size}
                  </div>
                  <div className="text-gray-500">Transferts actifs</div>
                </div>
                <div className="text-center">
                  <div
                    className={`text-2xl font-bold ${
                      socketStatus === "connected"
                        ? "text-green-600"
                        : "text-red-600"
                    }`}
                  >
                    {socketStatus === "connected" ? "✓" : "✗"}
                  </div>
                  <div className="text-gray-500">Signalisation</div>
                </div>
                <div className="text-center">
                  <div
                    className={`text-2xl font-bold ${
                      securityAlerts.filter((a) => a.level === "critical")
                        .length > 0
                        ? "text-red-600"
                        : securityAlerts.filter((a) => a.level === "warning")
                            .length > 0
                        ? "text-yellow-600"
                        : "text-green-600"
                    }`}
                  >
                    {
                      securityAlerts.filter((a) => a.level === "critical")
                        .length
                    }
                  </div>
                  <div className="text-gray-500">Alertes critiques</div>
                </div>
              </div>

              {/* Debug info détaillé avec sécurité */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-3 bg-gray-100 rounded text-xs">
                  <h4 className="font-semibold mb-2">Informations système</h4>
                  <p>
                    <strong>Socket Status:</strong> {socketStatus}
                  </p>
                  <p>
                    <strong>Socket ID:</strong> {socket?.id || "Non connecté"}
                  </p>
                  <p>
                    <strong>User ID:</strong> {user.id}
                  </p>
                  <p>
                    <strong>WebRTC Peers:</strong> {webrtcPeers.length}
                  </p>
                  <p>
                    <strong>Connected P2P:</strong>{" "}
                    {connectedWebRTCPeers.length}
                  </p>
                  <p>
                    <strong>Crypto Level:</strong>{" "}
                    {cryptoSupport?.securityLevel || "unknown"}
                  </p>
                  <p>
                    <strong>Encrypted Peers:</strong> {encryptedPeersCount}
                  </p>
                </div>

                <div className="p-3 bg-gray-100 rounded text-xs">
                  <h4 className="font-semibold mb-2">Métriques de transfert</h4>
                  {Array.from(transferSecurity.entries())
                    .slice(0, 4)
                    .map(([transferId, metrics]) => {
                      const transfer = activeTransfers.get(transferId);
                      return (
                        <div
                          key={transferId}
                          className="mb-2 border-b border-gray-300 pb-1"
                        >
                          <p className="font-medium">
                            {transfer?.fileName?.slice(0, 15) ||
                              transferId.slice(0, 8)}
                            ...
                          </p>
                          <p>Vérifications: {metrics.chunkVerifications}</p>
                          <p
                            className={
                              metrics.integrityFailures > 0
                                ? "text-red-600"
                                : ""
                            }
                          >
                            Échecs: {metrics.integrityFailures}
                          </p>
                          <p
                            className={
                              metrics.corruptionDetected
                                ? "text-red-600"
                                : "text-green-600"
                            }
                          >
                            Corruption:{" "}
                            {metrics.corruptionDetected ? "Oui" : "Non"}
                          </p>
                        </div>
                      );
                    })}
                  {transferSecurity.size === 0 && (
                    <p className="text-gray-500">
                      Aucune métrique de transfert
                    </p>
                  )}
                </div>

                <div className="p-3 bg-gray-100 rounded text-xs max-h-40 overflow-y-auto">
                  <h4 className="font-semibold mb-2">Logs sécurisés récents</h4>
                  {debugInfo.length === 0 ? (
                    <p className="text-gray-500">Aucun log disponible</p>
                  ) : (
                    debugInfo.map((log, index) => (
                      <p
                        key={index}
                        className={`text-xs mb-1 font-mono ${
                          log.includes("[SECURITY CRITICAL]")
                            ? "text-red-600"
                            : log.includes("[SECURITY WARNING]")
                            ? "text-yellow-600"
                            : log.includes("[SECURITY INFO]")
                            ? "text-blue-600"
                            : ""
                        }`}
                      >
                        {log}
                      </p>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
