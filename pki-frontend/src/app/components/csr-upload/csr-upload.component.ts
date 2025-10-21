import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { CsrService, CaCertificate } from '../../services/csr.service';
import { CaUser, UserService } from 'src/app/services/user.service';
import { User } from 'src/app/services/auth.service';

@Component({
  selector: 'app-csr-upload',
  templateUrl: './csr-upload.component.html',
  styleUrls: ['./csr-upload.component.css']
})
export class CsrUploadComponent implements OnInit {
  csrForm: FormGroup;
  availableCAs: CaUser[] = []; 

  pemContent: string | null = null;
  selectedFile: File | null = null;

  isLoading = false;
  successMessage = '';
  errorMessage = '';

  constructor(
    private fb: FormBuilder,
    private csrService: CsrService,
    private userService: UserService
  ) {
    // Inicijalizujemo formu sa svim potrebnim poljima i validatorima
    this.csrForm = this.fb.group({
      approverId: ['', Validators.required],
      requestedValidFrom: ['', Validators.required],
      requestedValidTo: ['', Validators.required],
    });
  }

  ngOnInit(): void {
    this.loadAvailableCAs();
  }

  loadAvailableCAs(): void {
    this.userService.getCaUsers().subscribe({
      next: (users) => { this.availableCAs = users; },
      error: (err) => { this.errorMessage = 'Greška pri učitavanju liste CA korisnika.'; }
    });
  }


  onFileSelected(event: any): void {
    const file: File = event.target.files[0];
    if (file) {
      this.selectedFile = file;
      this.errorMessage = '';
      this.successMessage = '';
      
      const reader = new FileReader();
      reader.onload = (e: any) => {
        this.pemContent = e.target.result;
      };
      reader.readAsText(this.selectedFile);
    }
  }

  onSubmit(): void {
    if (this.csrForm.invalid) {
      this.errorMessage = 'Molimo popunite sva obavezna polja.';
      return;
    }
    if (!this.pemContent) {
      this.errorMessage = 'Molimo vas da izaberete CSR fajl.';
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';
    this.successMessage = '';

    // Spajamo podatke iz forme i pročitani PEM sadržaj
    const payload = {
      pemContent: this.pemContent,
      ...this.csrForm.value
    };

    this.csrService.submitCsr(payload).subscribe({
      next: (response) => {
        this.isLoading = false;
        this.successMessage = `Zahtev uspešno poslat! ID vašeg zahteva je ${response.id}.`;
        this.csrForm.reset();
        this.selectedFile = null;
        this.pemContent = null;
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = err.error?.message || 'Došlo je do greške prilikom slanja zahteva.';
      }
    });
  }
}