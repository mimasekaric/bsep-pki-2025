import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { CertificateService } from '../../services/certificate.service';

@Component({
  selector: 'app-issue-certificate',
  templateUrl: './issue-certificate.component.html',
  styleUrls: ['./issue-certificate.component.css']
})
export class IssueCertificateComponent {
  certificateForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  isRootCertificate = false;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    private router: Router
  ) {
    this.certificateForm = this.fb.group({
      commonName: ['', [Validators.required]],
      organization: ['', [Validators.required]],
      organizationalUnit: ['', [Validators.required]],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
      validFrom: ['', [Validators.required]],
      validTo: ['', [Validators.required]],
      issuerSerialNumber: [''],
      subjectUserId: ['']
    });

    // Set default dates
    const now = new Date();
    const oneYearLater = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
    
    this.certificateForm.patchValue({
      validFrom: this.formatDateForInput(now),
      validTo: this.formatDateForInput(oneYearLater)
    });
  }

  formatDateForInput(date: Date): string {
    return date.toISOString().slice(0, 16);
  }

  toggleCertificateType() {
    this.isRootCertificate = !this.isRootCertificate;
    if (this.isRootCertificate) {
      this.certificateForm.get('issuerSerialNumber')?.clearValidators();
      this.certificateForm.get('issuerSerialNumber')?.setValue('');
    } else {
      this.certificateForm.get('issuerSerialNumber')?.setValidators([Validators.required]);
    }
    this.certificateForm.get('issuerSerialNumber')?.updateValueAndValidity();
  }

  onSubmit() {
    if (this.certificateForm.valid) {
      this.isLoading = true;
      this.errorMessage = '';
      this.successMessage = '';

      const formData = { ...this.certificateForm.value };
      
      // Convert dates to ISO format
      formData.validFrom = new Date(formData.validFrom).toISOString();
      formData.validTo = new Date(formData.validTo).toISOString();

      // Remove empty optional fields
      if (!formData.issuerSerialNumber) {
        delete formData.issuerSerialNumber;
      }
      if (!formData.subjectUserId) {
        delete formData.subjectUserId;
      }

      const request = this.isRootCertificate
        ? this.certificateService.issueRootCertificate(formData)
        : this.certificateService.issueCertificate(formData);

      request.subscribe({
        next: (response) => {
          console.log('Certificate issued successfully:', response);
          this.successMessage = 'Sertifikat je uspešno izdat!';
          this.isLoading = false;
          
          // Reset form after 2 seconds
          setTimeout(() => {
            this.certificateForm.reset();
            this.successMessage = '';
            const now = new Date();
            const oneYearLater = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
            this.certificateForm.patchValue({
              validFrom: this.formatDateForInput(now),
              validTo: this.formatDateForInput(oneYearLater)
            });
          }, 2000);
        },
        error: (error) => {
          console.error('Certificate issuance error:', error);
          this.errorMessage = error.error?.message || error.error || 'Greška pri izdavanju sertifikata';
          this.isLoading = false;
        }
      });
    } else {
      // Mark all fields as touched to show validation errors
      Object.keys(this.certificateForm.controls).forEach(key => {
        this.certificateForm.get(key)?.markAsTouched();
      });
    }
  }

  hasError(fieldName: string): boolean {
    const field = this.certificateForm.get(fieldName);
    return !!(field && field.invalid && field.touched);
  }

  getErrorMessage(fieldName: string): string {
    const field = this.certificateForm.get(fieldName);
    if (field?.errors) {
      if (field.errors['required']) return 'Ovo polje je obavezno';
      if (field.errors['email']) return 'Unesite validnu email adresu';
      if (field.errors['pattern']) return 'Unesite dvoslovnu oznaku države (npr. RS)';
    }
    return '';
  }
}
