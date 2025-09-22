// frontend/src/lib/p2p/WebRTCManager.ts - Version avec chiffrement
import { io, Socket } from "socket.io-client";
import {
  CryptoService,
  EncryptedData,
  FileFingerprint,
} from "../crypto/CryptoService";

export interface WebRTCPeer {
  id: string;
  username: string;
  connection?: RTCPeerConnection;
  dataChannel?: RTCDataChannel;
  status: "disconnected" | "connecting" | "connected" | "error";
  encryptionKey?: CryptoKey; // Clé de chiffrement pour ce pair
}

export interface SecureFileTransferData {
  type:
    | "file-offer"
    | "file-chunk"
    | "file-complete"
    | "file-accept"
    | "file-reject"
    | "key-exchange";
  transferId?: string;
  fileName?: string;
  fileSize?: number;
  chunkIndex?: number;
  totalChunks?: number;
  data?: string; // Encrypted base64 data
  fingerprint?: FileFingerprint;
  keyData?: string; // Encrypted transfer key
  iv?: string;
  error?: string;
}

export class WebRTCManager {
  private socket: Socket;
  private peers: Map<string, WebRTCPeer> = new Map();
  private masterKey?: CryptoKey; // Clé maître de l'utilisateur
  private onPeerConnected?: (peerId: string) => void;
  private onPeerDisconnected?: (peerId: string) => void;
  private onFileReceived?: (
    peerId: string,
    data: SecureFileTransferData
  ) => void;
  private onConnectionStatusChange?: (peerId: string, status: string) => void;
  private onEncryptionProgress?: (transferId: string, progress: number) => void;

  constructor(socketUrl: string) {
    this.socket = io(socketUrl, {
      transports: ["websocket", "polling"],
    });

    this.setupSocketListeners();
    this.initializeMasterKey();
  }

  // Initialiser la clé maître de l'utilisateur
  private async initializeMasterKey() {
    try {
      const stored = localStorage.getItem("p2p-master-key");
      if (stored) {
        this.masterKey = await CryptoService.importKey(stored);
        console.log("Master key loaded from storage");
      } else {
        this.masterKey = await CryptoService.generateKey();
        const exported = await CryptoService.exportKey(this.masterKey);
        localStorage.setItem("p2p-master-key", exported);
        console.log("New master key generated and stored");
      }
    } catch (error) {
      console.error("Error initializing master key:", error);
    }
  }

  private setupSocketListeners() {
    this.socket.on(
      "webrtc-signal",
      async (data: { fromPeerId: string; signal: any }) => {
        await this.handleSignal(data.fromPeerId, data.signal);
      }
    );
  }

  async connectToPeer(peerId: string, username: string): Promise<boolean> {
    console.log(
      `Initiating encrypted P2P connection to ${username} (${peerId})`
    );

    try {
      const peerConnection = new RTCPeerConnection({
        iceServers: [
          { urls: "stun:stun.l.google.com:19302" },
          { urls: "stun:stun1.l.google.com:19302" },
        ],
      });

      // Générer une clé de chiffrement unique pour ce pair
      const encryptionKey = await CryptoService.generateKey();

      const peer: WebRTCPeer = {
        id: peerId,
        username,
        connection: peerConnection,
        status: "connecting",
        encryptionKey,
      };

      this.peers.set(peerId, peer);
      this.notifyStatusChange(peerId, "connecting");

      const dataChannel = peerConnection.createDataChannel(
        "secureFileTransfer",
        {
          ordered: true,
          maxRetransmits: 3,
        }
      );

      peer.dataChannel = dataChannel;
      this.setupDataChannel(dataChannel, peerId);

      peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
          this.sendSignal(peerId, {
            type: "ice-candidate",
            candidate: event.candidate,
          });
        }
      };

      peerConnection.onconnectionstatechange = () => {
        const state = peerConnection.connectionState;
        console.log(`Connection state with ${username}: ${state}`);

        if (state === "connected") {
          peer.status = "connected";
          this.notifyStatusChange(peerId, "connected");
          this.exchangeEncryptionKey(peerId);
          this.onPeerConnected?.(peerId);
        } else if (state === "disconnected" || state === "failed") {
          peer.status = state === "failed" ? "error" : "disconnected";
          this.notifyStatusChange(peerId, peer.status);
          this.onPeerDisconnected?.(peerId);
        }
      };

      const offer = await peerConnection.createOffer();
      await peerConnection.setLocalDescription(offer);

      this.sendSignal(peerId, {
        type: "offer",
        offer: offer,
      });

      return true;
    } catch (error) {
      console.error("Error connecting to peer:", error);
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.status = "error";
        this.notifyStatusChange(peerId, "error");
      }
      return false;
    }
  }

  // Échanger les clés de chiffrement de manière sécurisée
  private async exchangeEncryptionKey(peerId: string) {
    const peer = this.peers.get(peerId);
    if (!peer?.dataChannel || !peer.encryptionKey || !this.masterKey) return;

    try {
      // Chiffrer la clé de transfert avec la clé maître
      const keyData = await CryptoService.exportKey(peer.encryptionKey);
      const keyBuffer = new TextEncoder().encode(keyData);
      const encryptedKey = await CryptoService.encrypt(
        keyBuffer.buffer,
        this.masterKey
      );
      const keyExchange: SecureFileTransferData = {
        type: "key-exchange",
        keyData: encryptedKey.data,
        iv: encryptedKey.iv,
      };

      peer.dataChannel.send(JSON.stringify(keyExchange));
      console.log("Encryption key sent to peer:", peerId);
    } catch (error) {
      console.error("Error exchanging encryption key:", error);
    }
  }

  private async handleSignal(fromPeerId: string, signal: any) {
    console.log("Received signal from", fromPeerId, ":", signal.type);

    let peer = this.peers.get(fromPeerId);

    try {
      switch (signal.type) {
        case "offer":
          if (!peer) {
            const peerConnection = new RTCPeerConnection({
              iceServers: [
                { urls: "stun:stun.l.google.com:19302" },
                { urls: "stun:stun1.l.google.com:19302" },
              ],
            });

            const encryptionKey = await CryptoService.generateKey();

            peer = {
              id: fromPeerId,
              username: `User-${fromPeerId.substring(0, 6)}`,
              connection: peerConnection,
              status: "connecting",
              encryptionKey,
            };

            this.peers.set(fromPeerId, peer);
          }

          peer.connection!.ondatachannel = (event) => {
            const channel = event.channel;
            peer!.dataChannel = channel;
            this.setupDataChannel(channel, fromPeerId);
          };

          peer.connection!.onicecandidate = (event) => {
            if (event.candidate) {
              this.sendSignal(fromPeerId, {
                type: "ice-candidate",
                candidate: event.candidate,
              });
            }
          };

          await peer.connection!.setRemoteDescription(signal.offer);
          const answer = await peer.connection!.createAnswer();
          await peer.connection!.setLocalDescription(answer);

          this.sendSignal(fromPeerId, {
            type: "answer",
            answer: answer,
          });

          break;

        case "answer":
          if (peer?.connection) {
            await peer.connection.setRemoteDescription(signal.answer);
          }
          break;

        case "ice-candidate":
          if (peer?.connection) {
            await peer.connection.addIceCandidate(signal.candidate);
          }
          break;
      }
    } catch (error) {
      console.error("Error handling signal:", error);
    }
  }

  private setupDataChannel(channel: RTCDataChannel, peerId: string) {
    console.log("Setting up secure data channel for peer:", peerId);

    channel.onopen = () => {
      console.log("Secure data channel opened with peer:", peerId);
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.status = "connected";
        this.notifyStatusChange(peerId, "connected");
        this.exchangeEncryptionKey(peerId);
        this.onPeerConnected?.(peerId);
      }
    };

    channel.onclose = () => {
      console.log("Data channel closed with peer:", peerId);
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.status = "disconnected";
        this.notifyStatusChange(peerId, "disconnected");
        this.onPeerDisconnected?.(peerId);
      }
    };

    channel.onerror = (error) => {
      console.error("Data channel error with peer:", peerId, error);
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.status = "error";
        this.notifyStatusChange(peerId, "error");
      }
    };

    channel.onmessage = (event) => {
      try {
        const data: SecureFileTransferData = JSON.parse(event.data);
        console.log("Received secure data from peer:", peerId, data.type);
        this.handleSecureMessage(peerId, data);
      } catch (error) {
        console.error("Error parsing received secure data:", error);
      }
    };
  }

  // Gérer les messages sécurisés
  private async handleSecureMessage(
    peerId: string,
    data: SecureFileTransferData
  ) {
    const peer = this.peers.get(peerId);

    switch (data.type) {
      case "key-exchange":
        if (data.keyData && data.iv && this.masterKey) {
          try {
            const encryptedKey = { data: data.keyData, iv: data.iv };
            const keyBuffer = await CryptoService.decrypt(
              encryptedKey,
              this.masterKey
            );
            const keyData = new TextDecoder().decode(keyBuffer);
            const peerKey = await CryptoService.importKey(keyData);

            if (peer) {
              peer.encryptionKey = peerKey;
              console.log("Encryption key received from peer:", peerId);
            }
          } catch (error) {
            console.error("Error processing key exchange:", error);
          }
        }
        break;

      default:
        // Transférer les autres messages vers le gestionnaire principal
        this.onFileReceived?.(peerId, data);
        break;
    }
  }

  // Envoyer un fichier avec chiffrement
  async sendFile(peerId: string, file: File): Promise<boolean> {
    const peer = this.peers.get(peerId);
    if (
      !peer?.dataChannel ||
      peer.dataChannel.readyState !== "open" ||
      !peer.encryptionKey
    ) {
      console.error(
        "Secure data channel or encryption key not ready for peer:",
        peerId
      );
      return false;
    }

    console.log(
      `Sending encrypted file ${file.name} (${file.size} bytes) to peer:`,
      peerId
    );

    try {
      const transferId = `transfer-${Date.now()}-${Math.random()
        .toString(36)
        .substr(2, 9)}`;

      // Notifier le début du chiffrement
      this.onEncryptionProgress?.(transferId, 0);

      // Chiffrer le fichier
      const { encryptedChunks, fingerprint } = await CryptoService.encryptFile(
        file,
        peer.encryptionKey,
        16384,
        (progress) => this.onEncryptionProgress?.(transferId, progress)
      );

      // Envoyer l'offre de fichier avec l'empreinte
      const fileOffer: SecureFileTransferData = {
        type: "file-offer",
        transferId,
        fileName: file.name,
        fileSize: file.size,
        totalChunks: encryptedChunks.length,
        fingerprint,
      };

      peer.dataChannel.send(JSON.stringify(fileOffer));
      console.log(`Encrypted file offer sent: ${file.name}`);

      // Envoyer chaque chunk chiffré
      for (let i = 0; i < encryptedChunks.length; i++) {
        const encryptedChunk = encryptedChunks[i];

        const chunkData: SecureFileTransferData = {
          type: "file-chunk",
          transferId,
          chunkIndex: i,
          totalChunks: encryptedChunks.length,
          data: encryptedChunk.data,
          iv: encryptedChunk.iv,
        };

        peer.dataChannel.send(JSON.stringify(chunkData));

        // Pause pour éviter de surcharger le canal
        await new Promise((resolve) => setTimeout(resolve, 5));
      }

      // Envoyer le signal de fin
      const complete: SecureFileTransferData = {
        type: "file-complete",
        transferId,
      };

      peer.dataChannel.send(JSON.stringify(complete));

      console.log("Encrypted file sent successfully");
      return true;
    } catch (error) {
      console.error("Error sending encrypted file:", error);
      return false;
    }
  }

  // Test des capacités cryptographiques
  async testCryptoSupport(): Promise<{
    supported: boolean;
    features: string[];
    errors: string[];
  }> {
    return await CryptoService.testCryptoSupport();
  }

  disconnectFromPeer(peerId: string) {
    const peer = this.peers.get(peerId);
    if (peer) {
      if (peer.dataChannel) {
        peer.dataChannel.close();
      }
      if (peer.connection) {
        peer.connection.close();
      }
      this.peers.delete(peerId);
      this.onPeerDisconnected?.(peerId);
    }
  }

  private sendSignal(targetPeerId: string, signal: any) {
    this.socket.emit("webrtc-signal", {
      targetPeerId,
      signal,
    });
  }

  private notifyStatusChange(peerId: string, status: string) {
    this.onConnectionStatusChange?.(peerId, status);
  }

  authenticate(token: string) {
    this.socket.emit("authenticate", token);
  }

  getPeer(peerId: string): WebRTCPeer | undefined {
    return this.peers.get(peerId);
  }

  getAllPeers(): WebRTCPeer[] {
    return Array.from(this.peers.values());
  }

  isConnectedToPeer(peerId: string): boolean {
    const peer = this.peers.get(peerId);
    return peer?.status === "connected" && !!peer.encryptionKey;
  }

  // Event listeners
  onPeerConnect(callback: (peerId: string) => void) {
    this.onPeerConnected = callback;
  }

  onPeerDisconnect(callback: (peerId: string) => void) {
    this.onPeerDisconnected = callback;
  }

  onFileReceive(
    callback: (peerId: string, data: SecureFileTransferData) => void
  ) {
    this.onFileReceived = callback;
  }

  onStatusChange(callback: (peerId: string, status: string) => void) {
    this.onConnectionStatusChange = callback;
  }

  onEncryptionProgressUpdate(
    callback: (transferId: string, progress: number) => void
  ) {
    this.onEncryptionProgress = callback;
  }

  cleanup() {
    this.peers.forEach((peer, peerId) => {
      this.disconnectFromPeer(peerId);
    });
    this.socket.disconnect();
  }
}
