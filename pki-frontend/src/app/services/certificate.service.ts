import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { CaCertificate } from './csr.service';
import { HttpHeaders } from '@angular/common/http';
import { AuthService } from './auth.service';

export interface CertificateIssueDTO {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  validFrom: string;
  validTo: string;
  issuerSerialNumber?: string;
  subjectUserId?: string;
}

export interface CertificateDetailsDTO {
  id: number;
  serialNumber: string;
  subjectDN: string;
  issuerSerialNumber: string;
  validFrom: string;
  validTo: string;
  type: string;
  revoked: boolean;
}

export interface UserCertificateDTO {
    userId: string; // UUID
    certificatePem: string; // CELI sertifikat u PEM formatu
    publicKeyPem: string; // Samo javni ključ iz sertifikata, ako ga backend može ekstrahovati
    // ... ostali podaci o sertifikatu
}

export interface IssuerDto {
  serialNumber: string;
  commonName: string;
  validFrom: string;
  validTo: string;
}

export interface CertificateWithPrivateKeyDTO {
  certificate: CertificateDetailsDTO;
  privateKeyPem: string;
}

export interface SubjectDto {
  id: string; 
  name: string;
  surname: string;
  role: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'https://localhost:8443/api/certificates';

  constructor(private http: HttpClient, private authService: AuthService) { }

  issueRootCertificate(certificateData: CertificateIssueDTO): Observable<CertificateDetailsDTO> {
    return this.http.post<CertificateDetailsDTO>(`${this.apiUrl}/issue-root`, certificateData);
  }

  issueCertificate(certificateData: CertificateIssueDTO): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/issue`, certificateData);
  }

  getUserCertificate(userId: string): Observable<UserCertificateDTO> {
    return this.http.get<UserCertificateDTO>(`${this.apiUrl}/${userId}/certificate`);
  }

   getMyPublicKey(): Observable<string> {
    return this.http.get(`${this.apiUrl}/my-public-key`, { responseType: 'text' });
  }


  getPublicKeyForUser(email: string): Observable<string> {
    return this.http.get(`${this.apiUrl}/public-key/${email}`, { responseType: 'text' });
  }

  getAvailableIssuers(): Observable<IssuerDto[]> {
    return this.http.get<IssuerDto[]>(`${this.apiUrl}/issuers`);
  }

  getPotentialSubjects(): Observable<SubjectDto[]> {
    return this.http.get<SubjectDto[]>(`${this.apiUrl}/potential-subjects`);
  }
    getMyCaCertificates(): Observable<CertificateDetailsDTO[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    
    // Pozivamo novi endpoint
    return this.http.get<CertificateDetailsDTO[]>(`${this.apiUrl}/ca`, { headers });
  }
  private createAuthHeaders(): HttpHeaders | null {
    const token = this.authService.getToken();
    if (!token) {
      return null;
    }
    return new HttpHeaders({
      'Content-Type': 'application/json', 
      'Authorization': `Bearer ${token}`
    });
  }
  
   getAllCertificates(): Observable<CertificateDetailsDTO[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    
    return this.http.get<CertificateDetailsDTO[]>(`${this.apiUrl}/adminCertificates`, { headers });
  }

  
  getChainForCaUser(): Observable<CertificateDetailsDTO[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    return this.http.get<CertificateDetailsDTO[]>(`${this.apiUrl}/caCertificates`, { headers });
  }

  
  getCertificatesForUser(): Observable<CertificateDetailsDTO[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));

    return this.http.get<CertificateDetailsDTO[]>(`${this.apiUrl}/endEntityCertificates`, { headers });
  }

    downloadCertificate(certificateId: number): Observable<Blob> {
    const headers = this.createAuthHeaders();
    if (!headers) {
      return throwError(() => new Error('Korisnik nije autentifikovan.'));
    }
    return this.http.get(`${this.apiUrl}/download/${certificateId}`, {
      headers: headers.delete('Content-Type'), 
      responseType: 'blob' 
    });
  }
}
