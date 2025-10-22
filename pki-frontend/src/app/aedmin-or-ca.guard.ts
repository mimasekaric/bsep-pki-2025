import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from './services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class AdminOrCaUserGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {}

  canActivate(): boolean {
    if (!this.authService.isLoggedIn()) {
      this.router.navigate(['/login']);
      return false;
    }


    const isAdmin = this.authService.hasRole('ROLE_ADMIN');
    const isCaUser = this.authService.hasRole('ROLE_CA_USER');

    if (isAdmin || isCaUser) {
      return true;
    } else {
  
      this.router.navigate(['/dashboard']);
      return false;
    }
  }
}