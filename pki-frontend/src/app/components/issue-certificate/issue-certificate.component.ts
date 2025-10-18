import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormArray } from '@angular/forms';
import { Router } from '@angular/router';
import { CertificateService, IssuerDto } from '../../services/certificate.service';

@Component({
  selector: 'app-issue-certificate',
  templateUrl: './issue-certificate.component.html',
  styleUrls: ['./issue-certificate.component.css']
})
export class IssueCertificateComponent implements OnInit {
  certificateForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  isRootCertificate = false;

  // Niz će sada biti tipiziran i čuvaće podatke sa backenda
  availableIssuers: IssuerDto[] = []; 

  // Promenljive za dinamičko ograničavanje datuma
  issuerValidFrom: string = '';
  issuerValidTo: string = '';

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    private router: Router
  ) {
    this.certificateForm = this.fb.group({});
  }

  ngOnInit(): void {
    this.initForm();
    // Odmah po učitavanju komponente, pozivamo metodu za dobavljanje izdavaoca
    this.loadIssuers(); 
  }

  initForm(): void {
    // ... (initForm metoda ostaje ista kao u prethodnom odgovoru)
    this.certificateForm = this.fb.group({
      commonName: ['', [Validators.required]],
      organization: ['', [Validators.required]],
      organizationalUnit: ['', [Validators.required]],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
      validFrom: ['', [Validators.required]],
      validTo: ['', [Validators.required]],
      issuerSerialNumber: [null],
      subjectUserId: [''],
      basicConstraints: this.fb.group({
        isCa: [false],
        pathLen: [{ value: null, disabled: true }]
      }),
      keyUsage: this.fb.group({
        digitalSignature: [false], nonRepudiation: [false], keyEncipherment: [false],
        dataEncipherment: [false], keyAgreement: [false], keyCertSign: [false], crlSign: [false]
      }),
      extendedKeyUsage: this.fb.group({
        serverAuth: [false], clientAuth: [false], codeSigning: [false],
        emailProtection: [false], timeStamping: [false]
      }),
      subjectAlternativeNames: this.fb.array([])
    });

    const now = new Date();
    const oneYearLater = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate());
    this.certificateForm.patchValue({
      validFrom: this.formatDateForInput(now),
      validTo: this.formatDateForInput(oneYearLater)
    });

    this.certificateForm.get('basicConstraints.isCa')?.valueChanges.subscribe(isCa => {
      const pathLenControl = this.certificateForm.get('basicConstraints.pathLen');
      isCa ? pathLenControl?.enable() : pathLenControl?.disable();
      if (!isCa) pathLenControl?.reset();
    });
  }

  // ===== NOVA, POPUNJENA METODA =====
  /**
   * Poziva CertificateService, dobavlja listu izdavaoca
   * i smešta je u lokalnu promenljivu `availableIssuers`.
   */
  loadIssuers(): void {
    this.isLoading = true; // Opciono: prikaži spinner dok se učitava
    this.certificateService.getAvailableIssuers().subscribe({
      next: (issuers) => {
        this.availableIssuers = issuers;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju liste izdavaoca. Proverite da li ste ulogovani.';
        this.isLoading = false;
        console.error(err);
      }
    });
  }
  
  // Metoda onIssuerChange sada radi sa realnim podacima
  onIssuerChange(event: any): void {
    const selectedSerial = event.target.value;
    const selectedIssuer = this.availableIssuers.find(i => i.serialNumber === selectedSerial);

    if (selectedIssuer) {
      this.issuerValidFrom = this.formatDateForInput(new Date(selectedIssuer.validFrom));
      this.issuerValidTo = this.formatDateForInput(new Date(selectedIssuer.validTo));
      
      this.certificateForm.get('validFrom')?.reset();
      this.certificateForm.get('validTo')?.reset();
    }
  }

  // Ostale metode (`formatDateForInput`, `toggleCertificateType`, `sanControls`, `addSan`, `removeSan`, `onSubmit`, `hasError`, `getErrorMessage`)
  // ostaju ISTE kao u prethodnom odgovoru.
  // ...
  // Kopirajte ostatak metoda odavde...
  formatDateForInput(date: Date): string {
    const offset = date.getTimezoneOffset();
    const adjustedDate = new Date(date.getTime() - (offset * 60 * 1000));
    return adjustedDate.toISOString().slice(0, 16);
  }

  toggleCertificateType(): void {
    // ... ista logika
    const issuerControl = this.certificateForm.get('issuerSerialNumber');
    if (this.isRootCertificate) {
      issuerControl?.clearValidators();
      issuerControl?.setValue(null);
      this.issuerValidFrom = '';
      this.issuerValidTo = '';
    } else {
      issuerControl?.setValidators([Validators.required]);
    }
    issuerControl?.updateValueAndValidity();
  }

  get sanControls() {
    return this.certificateForm.get('subjectAlternativeNames') as FormArray;
  }

  addSan(): void {
    // ... ista logika
    const sanGroup = this.fb.group({
      type: ['DNS', Validators.required],
      value: ['', Validators.required]
    });
    this.sanControls.push(sanGroup);
  }

  removeSan(index: number): void {
    this.sanControls.removeAt(index);
  }

  onSubmit(): void {
    // ... ista logika
    if (this.certificateForm.invalid) {
      this.certificateForm.markAllAsTouched();
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';
    this.successMessage = '';

    const formData = this.certificateForm.getRawValue();
    
    formData.validFrom = new Date(formData.validFrom).toISOString();
    formData.validTo = new Date(formData.validTo).toISOString();

    if (this.isRootCertificate) {
      delete formData.issuerSerialNumber;
    }
    if (!formData.subjectUserId) {
      delete formData.subjectUserId;
    }
    if (!formData.basicConstraints.isCa) {
        delete formData.basicConstraints.pathLen;
    }

    const request = this.isRootCertificate
      ? this.certificateService.issueRootCertificate(formData)
      : this.certificateService.issueCertificate(formData);

    request.subscribe({
      next: (response) => {
        this.successMessage = 'Sertifikat je uspešno izdat!';
        this.isLoading = false;
        
        setTimeout(() => {
          this.successMessage = '';
          this.isRootCertificate = false;
          this.initForm(); 
          this.loadIssuers(); // Ponovo učitaj listu izdavaoca za svaki slučaj
        }, 2500);
      },
      error: (error) => {
        this.errorMessage = error.error?.message || 'Došlo je do neočekivane greške.';
        this.isLoading = false;
        console.error('Greška pri izdavanju sertifikata:', error);
      }
    });
  }

  hasError(fieldName: string): boolean {
    // ... ista logika
    const field = this.certificateForm.get(fieldName);
    return !!(field && field.invalid && field.touched);
  }

  getErrorMessage(fieldName: string): string {
    // ... ista logika
    const field = this.certificateForm.get(fieldName);
    if (field?.errors) {
      if (field.errors['required']) return 'Ovo polje je obavezno';
      if (field.errors['email']) return 'Unesite validnu email adresu';
      if (field.errors['pattern']) return 'Unesite dvoslovnu oznaku države (npr. RS)';
    }
    return '';
  }
}