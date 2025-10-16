import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth.service';

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

@Component({
  selector: 'app-change-password',
  templateUrl: './change-password.component.html',
  styleUrls: ['./change-password.component.css']
})
export class ChangePasswordComponent {
  changePasswordForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';

  constructor(
    private fb: FormBuilder,
    private authService: AuthService
  ) {
    this.changePasswordForm = this.fb.group({
      currentPassword: ['', [Validators.required]],
      newPassword: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  passwordMatchValidator(form: FormGroup) {
    const newPassword = form.get('newPassword');
    const confirmPassword = form.get('confirmPassword');
    
    if (newPassword && confirmPassword && newPassword.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true });
      return { passwordMismatch: true };
    }
    return null;
  }

  onSubmit() {
    if (this.changePasswordForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      this.successMessage = '';

      this.authService.changePassword(this.changePasswordForm.value).subscribe({
        next: (response) => {
          this.successMessage = 'Lozinka je uspešno promenjena!';
          this.isLoading = false;
          this.changePasswordForm.reset();
        },
        error: (error) => {
          this.errorMessage = error.error?.message || 'Greška pri promeni lozinke';
          this.isLoading = false;
        }
      });
    }
  }
}