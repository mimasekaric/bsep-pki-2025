import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService, User } from '../../services/auth.service'; // Prilagodite putanju

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {
  isLoggedIn = false;
  currentUser: User | null = null;
  
  // Getter-i za lakšu proveru uloga u templejtu
  get isAdmin(): boolean {
    return this.currentUser?.role === 'ROLE_ADMIN';
  }

  get isCaUser(): boolean {
    return this.currentUser?.role === 'ROLE_CA_USER';
  }
  get mustChangePassword(): boolean { 
    return this.currentUser?.mustChangePassword === true;
  }

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // Pretplatimo se na promene statusa korisnika iz AuthService-a
    this.authService.currentUser$.subscribe(user => {
      this.currentUser = user;
      this.isLoggedIn = !!user; // !! pretvara user objekat (ili null) u boolean
    });
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}