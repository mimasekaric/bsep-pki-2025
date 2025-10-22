import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent {
  registerForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  passwordStrength: any = null;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.registerForm = this.fb.group({
      name: ['', [Validators.required, Validators.minLength(2)]],
      surname: ['', [Validators.required, Validators.minLength(2)]],
      email: ['', [Validators.required, Validators.email]],
      organisation: ['', [Validators.required, Validators.minLength(2)]],
      password: ['', [
        Validators.required, 
        Validators.minLength(8),
        Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      ]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  passwordMatchValidator(form: FormGroup) {
    const password = form.get('password');
    const confirmPassword = form.get('confirmPassword');
    
    if (password && confirmPassword && password.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true });
      return { passwordMismatch: true };
    }
    return null;
  }

  checkPasswordStrength() {
    const password = this.registerForm.get('password')?.value;
    if (!password) {
      this.passwordStrength = null;
      return;
    }

    let score = 0;
    let feedback = [];

    // Length check
    if (password.length >= 8) score += 1;
    else feedback.push('Najmanje 8 karaktera');

    // Lowercase check
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Mala slova');

    // Uppercase check
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Velika slova');

    // Number check
    if (/\d/.test(password)) score += 1;
    else feedback.push('Brojevi');

    // Special character check
    if (/[@$!%*?&]/.test(password)) score += 1;
    else feedback.push('Specijalni karakteri');

    // Length bonus
    if (password.length >= 12) score += 1;

    let level = 'weak';
    let text = 'Slaba lozinka';
    let color = 'red';

    if (score >= 5) {
      level = 'strong';
      text = 'Jaka lozinka';
      color = 'green';
    } else if (score >= 3) {
      level = 'medium';
      text = 'Srednja lozinka';
      color = 'orange';
    }

    this.passwordStrength = {
      level: level,
      text: text,
      color: color,
      score: score,
      feedback: feedback
    };
  }

  onSubmit() {
    if (this.registerForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      this.successMessage = '';

      this.authService.register(this.registerForm.value).subscribe({
        next: (response) => {
          this.successMessage = 'Registracija uspešna! Molimo proverite email za aktivaciju naloga.';
          this.isLoading = false;
          setTimeout(() => {
            this.router.navigate(['/login']);
          }, 3000);
        },
        error: (error) => {
          this.errorMessage = error.error?.message || 'Registracija neuspešna';
          this.isLoading = false;
        }
      });
    }
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }
}