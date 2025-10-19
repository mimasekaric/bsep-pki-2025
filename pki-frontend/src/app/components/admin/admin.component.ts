import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { UserService } from 'src/app/services/user.service';

export interface CAUserRequest {
  firstName: string;
  lastName: string;
  email: string;
  organization: string;
}

@Component({
  selector: 'app-admin',
  templateUrl: './admin.component.html',
  styleUrls: ['./admin.component.css']
})
export class AdminComponent {
  caUserForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';

  constructor(
    private fb: FormBuilder,
    private userService: UserService
  ) {
    this.caUserForm = this.fb.group({
      firstName: ['', [Validators.required, Validators.minLength(2)]],
      lastName: ['', [Validators.required, Validators.minLength(2)]],
      email: ['', [Validators.required, Validators.email]],
      organization: ['', [Validators.required, Validators.minLength(2)]]
    });
  }

  onSubmit() {
    if (this.caUserForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      this.successMessage = '';

      this.userService.createCAUser(this.caUserForm.value).subscribe({
        next: (response) => {
          this.successMessage = 'CA korisnik uspešno kreiran! Privremena lozinka je poslata na email.';
          this.isLoading = false;
          this.caUserForm.reset();
        },
        error: (error) => {
          this.errorMessage = error.error?.message || 'Greška pri kreiranju CA korisnika';
          this.isLoading = false;
        }
      });
    }
  }
}