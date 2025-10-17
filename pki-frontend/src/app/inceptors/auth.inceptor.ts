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

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          console.warn('Authentication expired or invalid. Redirecting to login.');

          this.authService.logout(); 
         
          this.router.navigate(['/login']); 

          // 3. Obavezno vrati Observable sa greškom da bi se lanac obrade grešaka nastavio
          // (npr. ako neka komponenta sluša specifičnu grešku).
          return throwError(() => new Error('Session expired or unauthorized.'));
        }

        // Za sve ostale greške koje nisu 401, samo ih prosledi dalje
        return throwError(() => error);
      })
    );
  }
}