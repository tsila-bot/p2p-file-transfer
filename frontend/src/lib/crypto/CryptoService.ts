// frontend/src/lib/crypto/CryptoService.ts
export interface EncryptedData {
  data: string; // Base64 encrypted data
  iv: string; // Base64 IV
  authTag?: string; // Base64 auth tag for GCM
}

export interface FileFingerprint {
  sha256: string;
  size: number;
  name: string;
  chunks: string[]; // Hash de chaque chunk
}

export class CryptoService {
  // Générer une clé de chiffrement aléatoire
  static async generateKey(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true, // extractable
      ["encrypt", "decrypt"]
    );
  }

  // Dériver une clé à partir d'un mot de passe
  static async deriveKeyFromPassword(
    password: string,
    salt: Uint8Array
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new Uint8Array(Array.from(salt)), // Conversion explicite
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  // Chiffrer des données
  static async encrypt(
    data: ArrayBuffer,
    key: CryptoKey
  ): Promise<EncryptedData> {
    // Générer un IV aléatoire
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96 bits pour AES-GCM

    try {
      const encrypted = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        data
      );

      return {
        data: this.arrayBufferToBase64(encrypted),
        iv: this.arrayBufferToBase64(iv.buffer),
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error}`);
    }
  }

  // Déchiffrer des données
  static async decrypt(
    encryptedData: EncryptedData,
    key: CryptoKey
  ): Promise<ArrayBuffer> {
    try {
      const data = this.base64ToArrayBuffer(encryptedData.data);
      const iv = this.base64ToArrayBuffer(encryptedData.iv);

      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(iv),
        },
        key,
        data
      );

      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error}`);
    }
  }

  // Générer un hash SHA-256
  static async generateHash(data: ArrayBuffer): Promise<string> {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return this.arrayBufferToHex(hashBuffer);
  }

  // Vérifier l'intégrité d'un chunk
  static async verifyChunkIntegrity(
    data: ArrayBuffer,
    expectedHash: string
  ): Promise<boolean> {
    const actualHash = await this.generateHash(data);
    return actualHash === expectedHash;
  }

  // Générer l'empreinte complète d'un fichier
  static async generateFileFingerprint(
    file: File,
    chunkSize: number = 16384
  ): Promise<FileFingerprint> {
    const chunks: string[] = [];
    const arrayBuffer = await file.arrayBuffer();
    const totalChunks = Math.ceil(file.size / chunkSize);

    // Calculer le hash de chaque chunk
    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const chunkData = arrayBuffer.slice(start, end);
      const chunkHash = await this.generateHash(chunkData);
      chunks.push(chunkHash);
    }

    // Hash global du fichier
    const fileHash = await this.generateHash(arrayBuffer);

    return {
      sha256: fileHash,
      size: file.size,
      name: file.name,
      chunks: chunks,
    };
  }

  // Chiffrer un fichier par chunks
  static async encryptFile(
    file: File,
    key: CryptoKey,
    chunkSize: number = 16384,
    onProgress?: (progress: number) => void
  ): Promise<{
    encryptedChunks: EncryptedData[];
    fingerprint: FileFingerprint;
  }> {
    const arrayBuffer = await file.arrayBuffer();
    const totalChunks = Math.ceil(file.size / chunkSize);
    const encryptedChunks: EncryptedData[] = [];

    // Générer l'empreinte avant chiffrement
    const fingerprint = await this.generateFileFingerprint(file, chunkSize);

    // Chiffrer chaque chunk
    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      const chunkData = arrayBuffer.slice(start, end);

      const encryptedChunk = await this.encrypt(chunkData, key);
      encryptedChunks.push(encryptedChunk);

      // Notifier la progression
      if (onProgress) {
        onProgress(Math.round(((i + 1) / totalChunks) * 100));
      }
    }

    return {
      encryptedChunks,
      fingerprint,
    };
  }

  // Déchiffrer et reconstituer un fichier
  static async decryptFile(
    encryptedChunks: EncryptedData[],
    key: CryptoKey,
    expectedFingerprint: FileFingerprint,
    onProgress?: (progress: number) => void
  ): Promise<{
    file: Blob;
    verified: boolean;
  }> {
    const decryptedChunks: ArrayBuffer[] = [];

    // Déchiffrer chaque chunk
    for (let i = 0; i < encryptedChunks.length; i++) {
      const decryptedChunk = await this.decrypt(encryptedChunks[i], key);
      decryptedChunks.push(decryptedChunk);

      // Vérifier l'intégrité du chunk
      const chunkHash = await this.generateHash(decryptedChunk);
      if (chunkHash !== expectedFingerprint.chunks[i]) {
        console.warn(`Chunk ${i} integrity check failed`);
      }

      // Notifier la progression
      if (onProgress) {
        onProgress(Math.round(((i + 1) / encryptedChunks.length) * 100));
      }
    }

    // Reconstituer le fichier
    const file = new Blob(decryptedChunks);

    // Vérification finale de l'intégrité du fichier complet
    const fileBuffer = await file.arrayBuffer();
    const fileHash = await this.generateHash(fileBuffer);
    const verified = fileHash === expectedFingerprint.sha256;

    return {
      file,
      verified,
    };
  }

  // Générer un mot de passe sécurisé pour les transferts
  static generateSecurePassword(length: number = 32): string {
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    return Array.from(array, (byte) => charset[byte % charset.length]).join("");
  }

  // Générer un salt aléatoire
  static generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  // Exporter une clé au format base64
  static async exportKey(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("raw", key);
    return this.arrayBufferToBase64(exported);
  }

  // Importer une clé depuis base64
  static async importKey(keyData: string): Promise<CryptoKey> {
    const keyBuffer = this.base64ToArrayBuffer(keyData);
    return await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
  }

  // Utilitaires de conversion
  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 8192;
    let result = "";

    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.slice(i, i + chunkSize);
      result += String.fromCharCode.apply(null, Array.from(chunk));
    }

    return btoa(result);
  }

  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes.buffer;
  }

  private static arrayBufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  }

  // Tester les fonctionnalités crypto du navigateur
  static async testCryptoSupport(): Promise<{
    supported: boolean;
    features: string[];
    errors: string[];
  }> {
    const features: string[] = [];
    const errors: string[] = [];

    try {
      // Test Web Crypto API
      if (!crypto || !crypto.subtle) {
        errors.push("Web Crypto API not available");
        return { supported: false, features, errors };
      }
      features.push("Web Crypto API");

      // Test AES-GCM
      const testKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      features.push("AES-GCM encryption");

      // Test SHA-256
      const testData = new TextEncoder().encode("test");
      await crypto.subtle.digest("SHA-256", testData);
      features.push("SHA-256 hashing");

      // Test PBKDF2
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        testData,
        "PBKDF2",
        false,
        ["deriveKey"]
      );
      features.push("PBKDF2 key derivation");

      return { supported: true, features, errors };
    } catch (error) {
      errors.push(`Crypto test failed: ${error}`);
      return { supported: false, features, errors };
    }
  }
}
