import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  recaptchaSiteKey = '6Ld_ZvIrAAAAAEm60_dYPHa_YFibZLFkOrbcD92A';
  private recaptchaWidgetId: number | undefined;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      //recaptcha: ['', [Validators.required]] // <-- DODATO POLJE ZA RECAPTCHA
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

//   onSubmit() {
//   if (this.loginForm.valid) {
//     this.isLoading = true;
//     this.errorMessage = '';

//     this.authService.login(this.loginForm.value).subscribe({
//       next: (response) => {
//         console.log('Login successful:', response);
        
       
//         if (response.mustChangePassword) {
 
//           this.router.navigate(['/change-password'], { 
//             queryParams: { forced: 'true' } 
//           });
//         } else {

//           this.router.navigate(['/certificates']);
//         }
        
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
// onSubmit() {
//   if (this.loginForm.valid) {
//     const recaptchaResponse = (window as any).grecaptcha.getResponse();
    
//     if (!recaptchaResponse) {
//       this.errorMessage = 'Molimo potvrdite da niste robot';
//       return;
//     }
    
//     // Dodaj recaptchaResponse u login request
//     const loginData = {
//       ...this.loginForm.value,
//       recaptchaResponse: recaptchaResponse
//     };

//       this.authService.login(loginData).subscribe({
//         next: (response) => {
//           console.log('Login successful:', response);
        
          
//           if (response.mustChangePassword) {
  
//             this.router.navigate(['/change-password'], { 
//               queryParams: { forced: 'true' } 
//             });
//           } else {
      
//             this.router.navigate(['/certificates']);
//           }
          
//           this.isLoading = false;
//         },
//         error: (error) => {
//           console.error('Login error:', error);
//           this.errorMessage = error.error?.message || 'Login failed';
//           this.isLoading = false;
//         }
//       });
//     }
//   }
  ngOnInit(): void {}

  ngAfterViewInit(): void {
    this.renderRecaptcha();
  }

  renderRecaptcha() {
    // Proveravamo da li je 'grecaptcha' objekat spreman
    if ((window as any).grecaptcha && (window as any).grecaptcha.render) {
      this.recaptchaWidgetId = (window as any).grecaptcha.render('recaptcha-container', {
        'sitekey': this.recaptchaSiteKey
      });
    } else {
      // Ako nije, probaj ponovo za 100ms
      setTimeout(() => this.renderRecaptcha(), 100);
    }
  }

  
onSubmit() {
    // 1. Provera validnosti osnovne forme (email i password)
    if (this.loginForm.invalid) {
        this.errorMessage = 'Molimo popunite email i lozinku.';
        return;
    }

    // Proveravamo da li je grecaptcha objekat uopšte spreman
    if (!(window as any).grecaptcha || !(window as any).grecaptcha.getResponse) {
        this.errorMessage = 'reCAPTCHA se još uvek učitava. Molimo sačekajte.';
        return;
    }

    // 2. Dobijamo reCAPTCHA token
    const recaptchaToken = (window as any).grecaptcha.getResponse(this.recaptchaWidgetId);

    // 3. Proveravamo da li je korisnik rešio reCAPTCHA-u
    if (!recaptchaToken) {
      this.errorMessage = 'Molimo potvrdite da niste robot.';
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';

    // 4. Kreiramo payload sa svim podacima za backend
    const payload = {
      email: this.loginForm.value.email,
      password: this.loginForm.value.password,
      recaptchaToken: recaptchaToken
    };

    // 5. Pozivamo AuthService
    this.authService.login(payload).subscribe({
      next: (response) => {
        this.isLoading = false;
        
        // 6. Logika za redirekciju nakon uspešnog logina
        if (response.mustChangePassword) {
          this.router.navigate(['/change-password'], { 
            queryParams: { forced: 'true' } 
          });
        } else {
          this.router.navigate(['/certificates']); // Ili /dashboard, gde god treba
        }
      },
      error: (error) => {
        this.isLoading = false;
        this.errorMessage = error.error?.message || 'Greška pri prijavi. Proverite email i lozinku.';
        
        // 7. Resetujemo reCAPTCHA widget da korisnik može ponovo da pokuša
        if ((window as any).grecaptcha && this.recaptchaWidgetId !== undefined) {
          (window as any).grecaptcha.reset(this.recaptchaWidgetId);
        }
      }
    });
  }
  goToRegister() {
    this.router.navigate(['/register']);
  }
  goToForgotPassword() {
    this.router.navigate(['/forgot-password']);
  }

  onRecaptchaSuccess(token: string) {
    console.log('reCAPTCHA verified:', token);
    // Možeš da sačuvaš token u komponenti ako treba
  }

  onRecaptchaExpired() {
    console.log('reCAPTCHA expired');
    this.errorMessage = 'reCAPTCHA je istekla. Molimo pokušajte ponovo.';
  }
}