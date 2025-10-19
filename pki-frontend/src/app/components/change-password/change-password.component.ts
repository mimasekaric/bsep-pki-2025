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
              this.router.navigate(['/issue-certificate']);
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
}