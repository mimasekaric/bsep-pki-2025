import { Injectable } from '@angular/core'; 
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { AuthService } from './auth.service';

// --- Interfejsi ostaju isti ---
export interface CsrSubmitPayload {
  pemContent: string;
  signingCertificateSerialNumber: string;
  requestedValidFrom: string;
  requestedValidTo: string;
}

export interface CsrResponse {
  id: number;
  status: string;
  pemContent: string;
  createdAt: string;
  owner: {
    email: string;
    // ...
  };
  
  caId: string;
  requestedValidFrom: string;
  requestedValidTo: string;
}

export interface CaCertificate {
  serialNumber: string;
  subjectDN: string;
  // ...
}
export interface ApproveCsrPayload {
  signingCertificateSerialNumber: string;
}

export interface RejectCsrPayload {
  rejectionReason: string;
}

@Injectable({
  providedIn: 'root'
})
export class CsrService {

  private baseUrl = 'http://localhost:8080/api';

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

 
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

  
  getValidCaCertificates(): Observable<CaCertificate[]> {
    const headers = this.createAuthHeaders();
    if (!headers) {
      return throwError(() => new Error('Korisnik nije autentifikovan.'));
    }

    return this.http.get<CaCertificate[]>(`${this.baseUrl}/certificates/ca`, { headers });
  }

  
  submitCsr(payload: CsrSubmitPayload): Observable<CsrResponse> {
    const headers = this.createAuthHeaders();
    if (!headers) {
      return throwError(() => new Error('Korisnik nije autentifikovan.'));
    }

    return this.http.post<CsrResponse>(`${this.baseUrl}/csr/submit`, payload, { headers });
  }


  approveCsr(csrId: number, payload: ApproveCsrPayload): Observable<any> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    
    return this.http.post<any>(`${this.baseUrl}/csr/${csrId}/approve`, payload, { headers });
  }

  getPendingCsrs(): Observable<CsrResponse[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    return this.http.get<CsrResponse[]>(`${this.baseUrl}/csr/pending`, { headers });
  }


  rejectCsr(csrId: number, payload: RejectCsrPayload): Observable<CsrResponse> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));
    return this.http.post<CsrResponse>(`${this.baseUrl}/csr/${csrId}/reject`, payload, { headers });
  }
}