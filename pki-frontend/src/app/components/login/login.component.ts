import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  loginForm: FormGroup;
  isLoading = false;
  errorMessage = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]]
    });
  }

  // onSubmit() {
  //   if (this.loginForm.valid) {
  //     this.isLoading = true;
  //     this.errorMessage = '';

  //     this.authService.login(this.loginForm.value).subscribe({
  //       next: (response) => {
  //         console.log('Login successful:', response);
  //         console.log('Current user:', this.authService.getCurrentUser());
  //         // Ukloni redirect na dashboard za sada
  //         this.isLoading = false;
  //       },
  //       error: (error) => {
  //         console.error('Login error:', error);
  //         this.errorMessage = error.error?.message || 'Login failed';
  //         this.isLoading = false;
  //       }
  //     });
  //   }
  // }

  onSubmit() {
  if (this.loginForm.valid) {
    this.isLoading = true;
    this.errorMessage = '';

    this.authService.login(this.loginForm.value).subscribe({
      next: (response) => {
        console.log('Login successful:', response);
        
       
        if (response.mustChangePassword) {
 
          this.router.navigate(['/change-password'], { 
            queryParams: { forced: 'true' } 
          });
        } else {

          this.router.navigate(['/certificates']);
        }
        
        this.isLoading = false;
      },
      error: (error) => {
        console.error('Login error:', error);
        this.errorMessage = error.error?.message || 'Login failed';
        this.isLoading = false;
      }
    });
  }
}

  goToRegister() {
    this.router.navigate(['/register']);
  }
  goToForgotPassword() {
    this.router.navigate(['/forgot-password']);
  }
}