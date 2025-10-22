import { Component, OnInit } from '@angular/core'; 
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router'; 
import { AuthService } from '../../services/auth.service';
import { UserService } from 'src/app/services/user.service';

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
export class ChangePasswordComponent implements OnInit { 
  changePasswordForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  isForced = false; 
  passwordStrength: any = null;

  constructor(
    private fb: FormBuilder,
    private userService: UserService,
    private router: Router,         
    private route: ActivatedRoute,
    private authService: AuthService 
  ) {
    this.changePasswordForm = this.fb.group({
      currentPassword: ['', [Validators.required]],
      newPassword: ['', [
        Validators.required, 
        Validators.minLength(8),
        
        Validators.pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      ]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator });
  }

  
  ngOnInit(): void {

    this.route.queryParams.subscribe(params => {
      this.isForced = params['forced'] === 'true';
    });
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

      this.userService.changePassword(this.changePasswordForm.value).subscribe({
        next: (response) => {
          this.successMessage = 'Lozinka je uspešno promenjena!';
          this.isLoading = false;
          this.changePasswordForm.reset();

          this.authService.processLoginResponse(response);
          
          // NOVA LOGIKA: Redirect nakon uspešne promene
          setTimeout(() => {
            if (this.isForced) {
              // Ako je forced, preusmeri na glavnu stranicu
              this.router.navigate(['/certificates']);
            }
            // Inače ostani na stranici
          }, 2000);
        },
        error: (error) => {
          this.errorMessage = error.error?.message || 'Greška pri promeni lozinke';
          this.isLoading = false;
        }
      });
    }
  }
  
  
  canNavigateAway(): boolean {
    return !this.isForced;
  }

    checkPasswordStrength() {
    // Prilagođeno da čita iz 'newPassword' polja
    const password = this.changePasswordForm.get('newPassword')?.value;
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
    if (/\d]/.test(password)) score += 1;
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
}