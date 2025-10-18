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
  successMessage = '';
  showNewPasswordForm = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.forgotPasswordForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      newPassword: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  passwordMatchValidator(form: FormGroup) {
    const newPassword = form.get('newPassword');
    const confirmPassword = form.get('confirmPassword');
    
    if (newPassword && confirmPassword && newPassword.value !== confirmPassword.value) {
      return { passwordMismatch: true };
    }
    return null;
  }

  onSubmitEmail() {
    if (this.forgotPasswordForm.get('email')?.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      
      // Simulacija slanja email-a za reset lozinke
      setTimeout(() => {
        this.isLoading = false;
        Swal.fire({
          icon: 'info',
          title: 'Email poslat!',
          text: 'Instrukcije za resetovanje lozinke su poslate na vašu email adresu.',
          confirmButtonColor: '#8b45ff',
          confirmButtonText: 'U redu'
        }).then(() => {
          this.showNewPasswordForm = true;
        });
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