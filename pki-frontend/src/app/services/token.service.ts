import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { HttpHeaders } from '@angular/common/http';

export interface TokenSession {
  token: string;
  device: string;
  ipAddress: string;
  lastActive: Date;
  current: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class TokenService {
  private apiUrl = 'http://localhost:8080/api/auth';

   private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('jwt_token'); 
    if (token) {
         console.log(`${token} found  tokeeen`);
      return new HttpHeaders().set('Authorization', `Bearer ${token}`);
     
    }
    console.warn('Access token not found in localStorage. Request might fail with 401.');
    return new HttpHeaders();
  }

  constructor(private http: HttpClient) {}

  getUserTokens(email: string): Observable<TokenSession[]> {
    return this.http.get<TokenSession[]>(`${this.apiUrl}/tokens/${email}`, { headers: this.getAuthHeaders() } );
  }

    revokeSpecificSession(token: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/revoke/${token}`,  { headers: this.getAuthHeaders() } );
  }

  revokeAllOtherSessions(userEmail: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/tokensdelete/${userEmail}`,  { headers: this.getAuthHeaders() });
  }
}
