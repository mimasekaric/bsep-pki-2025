import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.css']
})
export class ForgotPasswordComponent {
  forgotPasswordForm: FormGroup;
  isLoading = false;
  errorMessage = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.forgotPasswordForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]]
    });
  }

  onSubmitEmail() {
    if (this.forgotPasswordForm.get('email')?.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      
      const email = this.forgotPasswordForm.get('email')?.value;
      
      // Poziv ka backend servisu za slanje reset email-a
      this.authService.forgotPassword(email).subscribe({
        next: (response) => {
          this.isLoading = false;
          Swal.fire({
            icon: 'success',
            title: 'Email poslat!',
            text: 'Proverite vaš email inbox. Poslali smo vam link za resetovanje lozinke.',
            confirmButtonColor: '#8b45ff',
            confirmButtonText: 'U redu'
          });
        },
        error: (error) => {
          this.isLoading = false;
          Swal.fire({
            icon: 'error',
            title: 'Greška!',
            text: error.error?.message || 'Greška pri slanju email-a',
            confirmButtonColor: '#8b45ff'
          });
        }
      });
    }
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }

  hasError(fieldName: string): boolean {
    const field = this.forgotPasswordForm.get(fieldName);
    return !!(field && field.invalid && (field.dirty || field.touched));
  }

  getErrorMessage(fieldName: string): string {
    const field = this.forgotPasswordForm.get(fieldName);
    
    if (field?.errors) {
      if (field.errors['required']) {
        return 'Ovo polje je obavezno';
      }
      if (field.errors['email']) {
        return 'Unesite valjan email';
      }
    }

    return '';
  }
}