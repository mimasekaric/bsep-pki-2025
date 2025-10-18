import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export interface AuthResponse {
  accessToken: string;
  email: string;
  user: string;
}

export interface User {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8080/api/auth';
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient) {
    this.loadUserFromStorage();
  }

  login(credentials: LoginRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/login`, credentials)
      .pipe(
        tap(response => {
          this.setToken(response.accessToken); // Promijeni sa response.token na response.accessToken
          this.setCurrentUser(response.email);
        })
      );
  }

  register(userData: RegisterRequest): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, userData);
  }

  verifyEmail(token: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/verify-email?token=${token}`);
  }

  private setToken(token: string): void {
    localStorage.setItem('jwt_token', token);
  }


  public setCurrentUser(email: string): void {
    try {
      const user = this.decodeJWTToken(email);
      this.currentUserSubject.next(user);
      localStorage.setItem('currentUser', JSON.stringify(user));
    } catch (error) {
      console.error('Error setting current user:', error);
    }
  }

  private decodeJWTToken(email: string): User {
    const token = this.getToken();
    if (!token) {
      return {
        id: 0,
        firstName: '',
        lastName: '',
        email: email,
        role: 'USER'
      };
    }

    try {
      // Dekodiraj JWT token (base64)
      const payload = JSON.parse(atob(token.split('.')[1]));
      
      return {
        id: payload.sub ? parseInt(payload.sub) : 0,
        firstName: payload.firstName || '',
        lastName: payload.lastName || '',
        email: payload.sub || email,
        role: payload.scope ? payload.scope.split(' ')[0] : 'USER'
      };
    } catch (error) {
      console.error('Error decoding JWT token:', error);
      return {
        id: 0,
        firstName: '',
        lastName: '',
        email: email,
        role: 'USER'
      };
    }
  }

  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }

  private loadUserFromStorage(): void {
    try {
      const storedUser = localStorage.getItem('currentUser');
      if (storedUser && storedUser !== 'undefined' && storedUser !== 'null') {
        const user = JSON.parse(storedUser);
        this.currentUserSubject.next(user);
      }
    } catch (error) {
      console.error('Error loading user from storage:', error);
      // Očisti neispravne podatke
      localStorage.removeItem('currentUser');
      localStorage.removeItem('jwt_token');
    }
  }

  isAuthenticated(): boolean {
    const token = this.getToken();
    if (!token) return false;

    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const now = Math.floor(Date.now() / 1000);
      return payload.exp > now;
    } catch (error) {
      return false;
    }
  }

  logout(): void {
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
  }

  getToken(): string | null {
    return localStorage.getItem('jwt_token');
  }
}