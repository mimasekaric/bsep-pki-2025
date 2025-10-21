import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class CrlService {
 
  private apiUrl = 'http://localhost:8080/api/crl'; 

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  private createAuthHeaders(): HttpHeaders | null {
    const token = this.authService.getToken();
    if (!token) return null;
 
    return new HttpHeaders({ 'Authorization': `Bearer ${token}` });
  }


  downloadCrl(issuerSerial: string): Observable<Blob> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));

    return this.http.get(`${this.apiUrl}/${issuerSerial}`, {
      headers,
      responseType: 'blob' 
    });
  }
}