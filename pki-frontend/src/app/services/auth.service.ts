import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { map, tap } from 'rxjs/operators';
import { Router } from '@angular/router';

export interface LoginRequest {
  email: string;
  password: string;
  recaptchaToken: string;
}

export interface RegisterRequest {
  name: string;
  surname: string;
  email: string;
  password: string;
  confirmPassword: string;
  organisation: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface AuthResponse {
  accessToken: string;
  email: string;
  user: string;
  mustChangePassword?: boolean; 
}

export interface User {
  id: string;
  name: string;
  surname: string;
  email: string;
  role: string;
  mustChangePassword?: boolean;
}

export interface CAUserRequest {
  firstName: string;
  lastName: string;
  email: string;
  organization: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export interface UserOrganizationResponseDTO {
  organization: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://localhost:8443/api/auth';
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {
    this.loadUserFromStorage();
  }

  login(credentials: LoginRequest): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/login`, credentials)
      .pipe(
        tap(response => {
          this.setToken(response.accessToken);
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
        id: '',
        name: '',
        surname: '',
        email: email,
        role: 'USER',
        mustChangePassword: false
      };
    }

    try {
      // Dekodiraj JWT token (base64)
      const payload = JSON.parse(atob(token.split('.')[1]));
      
      return {
        id: payload.sub ? (payload.sub) : '',
        name: payload.name || '',
        surname: payload.surname || '',
        email: payload.sub || email,
        role: payload.scope ? payload.scope.split(' ')[0] : 'USER',
        mustChangePassword: payload.mustChangePassword || false
      };
    } catch (error) {
      console.error('Error decoding JWT token:', error);
      return {
        id: '',
        name: '',
        surname: '',
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
     this.router.navigate(['/login']);
    
  }

  getToken(): string | null {
    return localStorage.getItem('jwt_token');
  }

  forgotPassword(email: string): Observable<void> {
    const requestBody: ForgotPasswordRequest = { email };
    return this.http.post<void>(`${this.apiUrl}/forgot-password`, requestBody);
  }

  resetPassword(token: string, newPassword: string): Observable<string> {
    const requestBody: ResetPasswordRequest = { token, newPassword };
    return this.http.post(`${this.apiUrl}/reset-password`, requestBody, { responseType: 'text' });
  }

  fetchCurrentUserId(): Observable<{ id: number }> {
    return this.http.get<{ id: number }>(`${this.apiUrl}/me`);
  }

  fetchCurrentUserOrganization(): Observable<string> {
    return this.http.get<UserOrganizationResponseDTO>(`${this.apiUrl}/my-organisation`).pipe(
      map(response => {
        console.log("Primljen odgovor od servera:", response); 
        return response.organization;
      })
    );
  }


  processLoginResponse(response: AuthResponse): void {
  this.setToken(response.accessToken);
  this.setCurrentUser(response.email);
  }

  hasRole(expectedRole: string): boolean {
    if (!this.isLoggedIn()) {
      return false;
    }

    const token = this.getToken()!;
    try {
      const decodedToken: any = this.decodeJWTToken(token);
  
      const userRole = decodedToken.role || decodedToken.scope; 
      return userRole === expectedRole;
    } catch (error) {
      return false;
    }
  }

   isLoggedIn(): boolean {
    const token = this.getToken();
    if (!token) {
      return false;
    }

    return true;
  }
}
