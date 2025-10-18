import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css']
})
export class ResetPasswordComponent implements OnInit {
  resetPasswordForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  resetToken: string | null = null;
  tokenValid = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute
  ) {
    this.resetPasswordForm = this.fb.group({
      newPassword: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  ngOnInit() {
    // Čitanje tokena iz URL-a
    this.route.queryParams.subscribe(params => {
      this.resetToken = params['token'];
      
      if (!this.resetToken) {
        Swal.fire({
          icon: 'error',
          title: 'Nevažeći link!',
          text: 'Link za resetovanje lozinke nije validan.',
          confirmButtonColor: '#8b45ff'
        }).then(() => {
          this.router.navigate(['/login']);
        });
      } else {
        this.tokenValid = true;
        // Ovde možeš dodati validaciju tokena sa backend-om
        // this.validateToken(this.resetToken);
      }
    });
  }

  passwordMatchValidator(form: FormGroup) {
    const newPassword = form.get('newPassword');
    const confirmPassword = form.get('confirmPassword');
    
    if (newPassword && confirmPassword && newPassword.value !== confirmPassword.value) {
      return { passwordMismatch: true };
    }
    return null;
  }

  // Opciona validacija tokena sa backend-om
  // validateToken(token: string) {
  //   this.authService.validateResetToken(token).subscribe({
  //     next: (response) => {
  //       this.tokenValid = true;
  //     },
  //     error: (error) => {
  //       Swal.fire({
  //         icon: 'error',
  //         title: 'Link je istekao!',
  //         text: 'Link za resetovanje lozinke je istekao ili nije validan.',
  //         confirmButtonColor: '#8b45ff'
  //       }).then(() => {
  //         this.router.navigate(['/forgot-password']);
  //       });
  //     }
  //   });
  // }

  onSubmit() {
    if (this.resetPasswordForm.valid && this.resetToken) {
      this.isLoading = true;
      this.errorMessage = '';

      const resetData = {
        token: this.resetToken,
        newPassword: this.resetPasswordForm.get('newPassword')?.value
      };

      // Poziv ka backend servisu za reset lozinke sa tokenom
      // this.authService.resetPasswordWithToken(resetData).subscribe({
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
    const field = this.resetPasswordForm.get(fieldName);
    return !!(field && field.invalid && (field.dirty || field.touched));
  }

  getErrorMessage(fieldName: string): string {
    const field = this.resetPasswordForm.get(fieldName);
    
    if (field?.errors) {
      if (field.errors['required']) {
        return 'Ovo polje je obavezno';
      }
      if (field.errors['minlength']) {
        return `Minimum ${field.errors['minlength'].requiredLength} karaktera`;
      }
    }

    if (fieldName === 'confirmPassword' && this.resetPasswordForm.errors?.['passwordMismatch']) {
      return 'Lozinke se ne poklapaju';
    }

    return '';
  }

  isPasswordLengthValid(): boolean {
    const password = this.resetPasswordForm.get('newPassword')?.value || '';
    return password.length >= 8;
  }

  hasUpperCase(): boolean {
    const password = this.resetPasswordForm.get('newPassword')?.value || '';
    return /[A-Z]/.test(password);
  }

  hasLowerCase(): boolean {
    const password = this.resetPasswordForm.get('newPassword')?.value || '';
    return /[a-z]/.test(password);
  }

  hasNumber(): boolean {
    const password = this.resetPasswordForm.get('newPassword')?.value || '';
    return /[0-9]/.test(password);
  }

  hasSpecialChar(): boolean {
    const password = this.resetPasswordForm.get('newPassword')?.value || '';
    return /[!@#$%^&*(),.?":{}|<>]/.test(password);
  }
}