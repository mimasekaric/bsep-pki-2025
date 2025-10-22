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
 const token = this.authService.getToken(); // Pretpostavimo da ova metoda ispravno vraća token

    // 2. Kloniraj zahtev i dodaj Authorization header, AKO token postoji
    if (token) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
      console.log('Token je pronadjen i Authorization header je postavljen.'); // Log za debug
    } else {
      console.log('Token NIJE pronadjen, Authorization header NIJE postavljen.'); // Log za debug
    }
    return next.handle(request).pipe(
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