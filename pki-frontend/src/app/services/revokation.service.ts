import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { AuthService } from './auth.service';

export interface RevocationRequest {
  reason: string;
}


export interface RevocationResponse {
  message: string; 
}


@Injectable({
  providedIn: 'root'
})
export class RevokationService {

  private apiUrl = 'http://localhost:8080/api/revoke';
  constructor(private authService: AuthService, private http: HttpClient) { }

  private createAuthHeaders(): HttpHeaders | null {
    const token = this.authService.getToken();
    if (!token) return null;
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    });
  }


  revokeCertificate(serialNumber: string, reason: string): Observable<any> {
    const headers = this.createAuthHeaders();
    if (!headers) {
      return throwError(() => new Error('Korisnik nije autentifikovan.'));
    }

    const payload: RevocationRequest = { reason: reason };


    return this.http.post<any>(`${this.apiUrl}/${serialNumber}`, payload, { headers });
  }
}
