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

export interface CertificateWithPrivateKeyDTO {
  certificate: CertificateDetailsDTO;
  privateKeyPem: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'http://localhost:8080/api/certificates';

  constructor(private http: HttpClient, private authService: AuthService) { }

  issueRootCertificate(certificateData: CertificateIssueDTO): Observable<CertificateDetailsDTO> {
    return this.http.post<CertificateDetailsDTO>(`${this.apiUrl}/issue-root`, certificateData);
  }

  issueCertificate(certificateData: CertificateIssueDTO): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/issue`, certificateData);
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
}
