import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse 
} from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { Router } from '@angular/router'; 
import { AuthService } from '../services/auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(
    private router: Router,
    private authService: AuthService 
  ) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    
    // ==========================================================
    // ==== NOVI DEO: DODAVANJE TOKENA U ODLAZNI ZAHTEV =========
    // ==========================================================
    
    // 1. Uzmi token iz AuthService-a (koji ga čita iz localStorage)
    const token = this.authService.getToken();
    let authReq = request; // Po defaultu, zahtev ostaje nepromenjen

    // 2. Ako token postoji, kloniraj zahtev i dodaj mu Authorization header
    if (token) {
      authReq = request.clone({
        headers: request.headers.set('Authorization', `Bearer ${token}`)
      });
      console.log('AuthInterceptor: Token found, adding Authorization header.');
    } else {
      console.warn('AuthInterceptor: No token found. Sending request without token.');
    }
    
    // ==========================================================
    // ==== VAŠ POSTOJEĆI DEO: RUKOVANJE GREŠKAMA ===============
    // ==========================================================

    // 3. Prosledi novi (ili stari) zahtev dalje i uhvati potencijalne greške
    return next.handle(authReq).pipe(
      catchError((error: HttpErrorResponse) => {
        // 4. Ako server vrati 401, to znači da je token nevalidan ili istekao
        if (error.status === 401) {
          console.error('AuthInterceptor: Received 401 Unauthorized. Token is invalid or expired.');

          // Uradi logout da se obriše nevalidan token
          this.authService.logout(); 
         
          // Preusmeri korisnika na login stranicu
          this.router.navigate(['/login']); 

          // Vrati novu grešku da bi se lanac prekinuo
          return throwError(() => new Error('Session expired or unauthorized.'));
        }

        // 5. Za sve ostale greške (403, 404, 500...), samo ih prosledi dalje
        return throwError(() => error);
      })
    );
  }
}