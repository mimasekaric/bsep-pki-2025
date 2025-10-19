import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { AuthResponse, AuthService, ChangePasswordRequest } from './auth.service';

export interface CaUser {
  id: string; // UUID je string
  name: string;
  surname: string;
  email: string;
}

export interface CAUserRequest {
  firstName: string;
  lastName: string;
  email: string;
  organization: string;
}

export interface UserResponse {
  id: string;
  name: string;
  surname: string;
  email: string;
  role: string;
}
@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = 'http://localhost:8080/api/users';

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  private createAuthHeaders(): HttpHeaders | null {
    const token = this.authService.getToken();
    if (!token) return null;
    return new HttpHeaders({ 'Authorization': `Bearer ${token}` });
  }

  /**
   * Dohvata listu svih korisnika koji su CA (ADMIN ili CA_USER).
   */
  getCaUsers(): Observable<CaUser[]> {
    const headers = this.createAuthHeaders();
    if (!headers) return throwError(() => new Error('Korisnik nije autentifikovan.'));

    return this.http.get<CaUser[]>(`${this.apiUrl}/ca`, { headers });
  }

  createCAUser(userData: CAUserRequest): Observable<UserResponse> { // <-- DEFINICIJA METODE
    const headers = this.createAuthHeaders();
    if (!headers) {
      // Ako nema tokena, admin nije ulogovan. Vraćamo grešku.
      return throwError(() => new Error('Admin nije autentifikovan.'));
    }

    // Pozivamo novi endpoint koji smo definisali na backendu
    return this.http.post<UserResponse>(`${this.apiUrl}/create-ca-user`, userData, { headers });
  }
   changePassword(changePasswordData: ChangePasswordRequest): Observable<AuthResponse> {
     const token = this.authService.getToken();
    return this.http.post<AuthResponse>(`${this.apiUrl}/change-password`, changePasswordData, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
  }
  
}