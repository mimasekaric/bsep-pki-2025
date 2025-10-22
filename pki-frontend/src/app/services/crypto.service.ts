// src/app/services/crypto.service.ts
import { Injectable } from '@angular/core';
import { Observable, from, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {

  constructor() { }

  // --- Generisanje ključeva i CSR-a (opciono, ako to želite na frontendu) ---
  // Ova funkcionalnost nije direktno vezana za password manager, ali je deo PKI sistema
  // i omogućava korisniku da generiše sopstveni par ključeva ako ga već nema.
  // Za sada ćemo se fokusirati na uvoz/korišćenje postojećih ključeva.

  // --- Uvoz ključeva ---
  // Uvoz privatnog ključa iz PEM stringa
  importPrivateKey(pem: string): Observable<CryptoKey> {
    const binaryDer = this.pemToArrayBuffer(pem);
    return from(crypto.subtle.importKey(
      "pkcs8", // Format privatnog ključa
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true, // extractable
      ["decrypt"]
    )).pipe(
      catchError(error => {
        console.error("Error importing private key:", error);
        return throwError(() => new Error('Failed to import private key. Make sure it\'s a valid PKCS#8 PEM string.'));
      })
    );
  }

  // Uvoz javnog ključa iz PEM stringa
  importPublicKey(pem: string): Observable<CryptoKey> {
    const binaryDer = this.pemToArrayBuffer(pem);
    return from(crypto.subtle.importKey(
      "spki", // Format javnog ključa
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true, // extractable
      ["encrypt"]
    )).pipe(
      catchError(error => {
        console.error("Error importing public key:", error);
        return throwError(() => new Error('Failed to import public key. Make sure it\'s a valid SPKI PEM string.'));
      })
    );
  }

  // --- Enkripcija/Dekripcija ---

  // Enkriptuje tekst koristeći javni ključ
  encrypt(publicKey: CryptoKey, plaintext: string): Observable<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    return from(crypto.subtle.encrypt(
     { name: "RSA-OAEP"},

      publicKey,
      data
    )).pipe(
      map(buffer => this.arrayBufferToBase64(buffer)),
      catchError(error => {
        console.error("Error encrypting data:", error);
        return throwError(() => new Error('Failed to encrypt data.'));
      })
    );
  }

  // Dekriptuje enkriptovani base64 string koristeći privatni ključ
  decrypt(privateKey: CryptoKey, encryptedBase64: string): Observable<string> {
    const encryptedBuffer = this.base64ToArrayBuffer(encryptedBase64);
    return from(crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedBuffer
    )).pipe(
      map(buffer => {
        const decoder = new TextDecoder();
        return decoder.decode(buffer);
      }),
      catchError(error => {
        console.error("Error decrypting data:", error);
        return throwError(() => new Error('Failed to decrypt data. Ensure the correct private key is used.'));
      })
    );
  }

  // --- Pomoćne funkcije za konverziju ---

  private pemToArrayBuffer(pem: string): ArrayBuffer {
    const base64 = pem
      .replace(/-----BEGIN (RSA )?(PRIVATE|PUBLIC) KEY-----/, '')
      .replace(/-----END (RSA )?(PRIVATE|PUBLIC) KEY-----/, '')
      .replace(/[\n\r]/g, '');
    return this.base64ToArrayBuffer(base64);
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }
}