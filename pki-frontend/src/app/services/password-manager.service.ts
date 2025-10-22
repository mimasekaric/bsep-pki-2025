// src/app/services/password-manager.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';



export interface PasswordEntryDTO {
    id: string;
    siteName: string;
    username: string;
    ownerUsername:string;
    ownerId: string; // UUID
    createdAt: string; // LocalDateTime
    sharedWith: { [userId: string]: string }; // Mapa UUID-a i enkriptovanih lozinki
}

export interface PasswordEntryRequestDTO {
    siteName: string;
    username: string;
    encryptedPassword: string;
}

export interface SharePasswordDTO {
    shareWithUserName: string; // UUID
    reEncryptedPassword: string;
}

// src/app/dtos/user-dtos.ts
export interface UserCertificateDTO {
    userId: string; // UUID
    certificatePem: string; // CELI sertifikat u PEM formatu
    publicKeyPem: string; // Samo javni ključ iz sertifikata, ako ga backend može ekstrahovati
    // ... ostali podaci o sertifikatu
}

@Injectable({
  providedIn: 'root'
})
export class PasswordManagerService {
  private apiUrl = 'https://localhost:8443/api/password-manager';

  constructor(private http: HttpClient) { }

  createPasswordEntry(dto: PasswordEntryRequestDTO): Observable<PasswordEntryDTO> {
    return this.http.post<PasswordEntryDTO>(this.apiUrl, dto);
  }

  getUserPasswordEntries(): Observable<PasswordEntryDTO[]> {
    return this.http.get<PasswordEntryDTO[]>(this.apiUrl);
  }

  getPasswordEntryById(id: string): Observable<PasswordEntryDTO> {
    return this.http.get<PasswordEntryDTO>(`${this.apiUrl}/${id}`);
  }

  getEncryptedPasswordForUser(id: String): Observable<string> {
    return this.http.get(`${this.apiUrl}/${id}/encrypted-password`, { responseType: 'text' });
  }

  sharePasswordEntry(id: String, dto: SharePasswordDTO): Observable<PasswordEntryDTO> {
    return this.http.post<PasswordEntryDTO>(`${this.apiUrl}/${id}/share`, dto);
  }

  deletePasswordEntry(id: String): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
}