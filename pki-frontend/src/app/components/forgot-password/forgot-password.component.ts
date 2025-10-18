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
      // this.authService.sendResetPasswordEmail(email).subscribe({
      //   next: (response) => {
      //     this.isLoading = false;
      //     Swal.fire({
      //       icon: 'success',
      //       title: 'Email poslat!',
      //       text: 'Proverite vaš email inbox. Poslali smo vam link za resetovanje lozinke.',
      //       confirmButtonColor: '#8b45ff',
      //       confirmButtonText: 'U redu'
      //     });
      //   },
      //   error: (error) => {
      //     this.isLoading = false;
      //     Swal.fire({
      //       icon: 'error',
      //       title: 'Greška!',
      //       text: error.error?.message || 'Greška pri slanju email-a',
      //       confirmButtonColor: '#8b45ff'
      //     });
      //   }
      // });

      // Simulacija slanja email-a za reset lozinke
      // U realnoj aplikaciji, backend će poslati email sa linkom:
      // http://localhost:4200/reset-password?token=JWT_TOKEN
      setTimeout(() => {
        this.isLoading = false;
        Swal.fire({
          icon: 'success',
          title: 'Email poslat!',
          text: 'Proverite vaš email inbox. Poslali smo vam link za resetovanje lozinke.',
          confirmButtonColor: '#8b45ff',
          confirmButtonText: 'U redu'
        });
        
        // Za testiranje: simuliraj token i automatski preusmeri
        // Ukloni ovo u produkciji!
        console.log('Test link: http://localhost:4200/reset-password?token=test-jwt-token-12345');
      }, 1500);
    }
  }

  onSubmitNewPassword() {
    if (this.forgotPasswordForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';

      const resetData = {
        email: this.forgotPasswordForm.get('email')?.value,
        newPassword: this.forgotPasswordForm.get('newPassword')?.value
      };

      // Poziv ka backend servisu za reset lozinke
      // this.authService.resetPassword(resetData).subscribe({
      //   next: (response) => {
      //     this.isLoading = false;
      //     Swal.fire({
      //       icon: 'success',
      //       title: 'Uspešno!',
      //       text: 'Lozinka je uspešno resetovana!',
      //       confirmButtonColor: '#8b45ff',
      //       confirmButtonText: 'U redu'
      //     }).then(() => {
      //       this.router.navigate(['/login']);
      //     });
      //   },
      //   error: (error) => {
      //     this.isLoading = false;
      //     Swal.fire({
      //       icon: 'error',
      //       title: 'Greška!',
      //       text: error.error?.message || 'Greška pri promeni lozinke',
      //       confirmButtonColor: '#8b45ff'
      //     });
      //   }
      // });

      // Simulacija uspešne promene lozinke
      setTimeout(() => {
        this.isLoading = false;
        Swal.fire({
          icon: 'success',
          title: 'Uspešno!',
          text: 'Lozinka je uspešno resetovana!',
          confirmButtonColor: '#8b45ff',
          confirmButtonText: 'U redu'
        }).then(() => {
          this.router.navigate(['/login']);
        });
      }, 1500);
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
      if (field.errors['minlength']) {
        return `Minimum ${field.errors['minlength'].requiredLength} karaktera`;
      }
    }

    if (fieldName === 'confirmPassword' && this.forgotPasswordForm.errors?.['passwordMismatch']) {
      return 'Lozinke se ne poklapaju';
    }

    return '';
  }

  hasSpecialChar(): boolean {
    const password = this.forgotPasswordForm.get('newPassword')?.value || '';
    return /[!@#$%^&*(),.?":{}|<>]/.test(password);
  }

  isPasswordLengthValid(): boolean {
    const password = this.forgotPasswordForm.get('newPassword')?.value || '';
    return password.length >= 8;
  }

  hasUpperCase(): boolean {
    const password = this.forgotPasswordForm.get('newPassword')?.value || '';
    return /[A-Z]/.test(password);
  }

  hasLowerCase(): boolean {
    const password = this.forgotPasswordForm.get('newPassword')?.value || '';
    return /[a-z]/.test(password);
  }

  hasNumber(): boolean {
    const password = this.forgotPasswordForm.get('newPassword')?.value || '';
    return /[0-9]/.test(password);
  }
}