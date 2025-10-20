import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormArray } from '@angular/forms';
import { Router } from '@angular/router';
import { CertificateService, IssuerDto } from '../../services/certificate.service';
import { AuthService } from 'src/app/services/auth.service';
import { Subscription } from 'rxjs';

// Definišemo Enum (ili tip) za CertificateType
type CertificateType = 'ROOT' | 'INTERMEDIATE' | 'END_ENTITY';

@Component({
  selector: 'app-issue-certificate',
  templateUrl: './issue-certificate.component.html',
  styleUrls: ['./issue-certificate.component.css']
})
export class IssueCertificateComponent implements OnInit, OnDestroy {
  certificateForm: FormGroup;
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  isRootCertificate = false;

  availableIssuers: IssuerDto[] = []; 

  issuerValidFrom: string = '';
  issuerValidTo: string = '';
  issuerValidFromDate: Date | null = null;
  issuerValidToDate: Date | null = null;

  private currentUserId: number | null = null;
  private userSubscription: Subscription;

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    private router: Router,
    private authService: AuthService
  ) {
    this.certificateForm = this.fb.group({});
    this.userSubscription = this.authService.currentUser$.subscribe(user => {
      if (user && user.id) {
        this.currentUserId = user.id;
        console.log('ID ulogovanog korisnika je uspešno učitan:', this.currentUserId);
      } else {
        console.log('Korisnik trenutno nije ulogovan ili podaci nisu dostupni.');
        this.currentUserId = null;
      }
    });
  }

  ngOnDestroy(): void {
    if (this.userSubscription) {
      this.userSubscription.unsubscribe();
    }
  }

  ngOnInit(): void {
    this.initForm();
    this.loadIssuers(); 
  }

  initForm(): void {
    this.certificateForm = this.fb.group({
      commonName: ['', [Validators.required]],
      organization: ['', [Validators.required]],
      organizationalUnit: ['', [Validators.required]],
      country: ['', [Validators.required, Validators.pattern(/^[A-Z]{2}$/)]],
      email: ['', [Validators.required, Validators.email]],
      validFrom: ['', [Validators.required]],
      validTo: ['', [Validators.required]],
      issuerSerialNumber: [null],
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

  loadIssuers(): void {
    this.isLoading = true;
    this.certificateService.getAvailableIssuers().subscribe({
      next: (issuers) => {
        this.availableIssuers = issuers;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju liste izdavaoca.';
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  onIssuerChange(event: any): void {
    const selectedSerial = event.target.value;
    const selectedIssuer = this.availableIssuers.find(i => i.serialNumber == selectedSerial);

    if (selectedIssuer) {
      const validFrom = new Date(selectedIssuer.validFrom);
      const validTo = new Date(selectedIssuer.validTo);
      
      this.issuerValidFrom = this.formatDateForInput(validFrom);
      this.issuerValidTo = this.formatDateForInput(validTo);
      this.issuerValidFromDate = validFrom;
      this.issuerValidToDate = validTo;
      
      this.certificateForm.get('validFrom')?.reset();
      this.certificateForm.get('validTo')?.reset();
    } else {
      this.issuerValidFrom = '';
      this.issuerValidTo = '';
      this.issuerValidFromDate = null;
      this.issuerValidToDate = null;
    }
  }

  formatDateForInput(date: Date): string {
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  }

  toggleCertificateType(): void {
    const issuerControl = this.certificateForm.get('issuerSerialNumber');
    if (this.isRootCertificate) {
      issuerControl?.clearValidators();
      issuerControl?.setValue(null);
    } else {
      issuerControl?.setValidators([Validators.required]);
    }
    issuerControl?.updateValueAndValidity();
    
    this.issuerValidFrom = '';
    this.issuerValidTo = '';
    this.issuerValidFromDate = null;
    this.issuerValidToDate = null;
  }

  get sanControls() {
    return this.certificateForm.get('subjectAlternativeNames') as FormArray;
  }

  addSan(): void {
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
    if (this.certificateForm.invalid) {
      this.certificateForm.markAllAsTouched();
      return;
    }

    this.isLoading = true;
    this.errorMessage = '';
    this.successMessage = '';

    this.authService.fetchCurrentUserId().subscribe({
      
      next: (userWithId) => {
        
        if (!userWithId || !userWithId.id) {
          this.errorMessage = "ID korisnika nije pronađen na serveru. Izdavanje je prekinuto.";
          this.isLoading = false;
          console.error("KRITIČNA GREŠKA: Odgovor sa /api/users/me je neispravan.", userWithId);
          return;
        }

        console.log(`Dobijen je ispravan ID sa servera: ${userWithId.id}`);
        const subjectUserIdToSend = userWithId.id.toString();

        const formValue = this.certificateForm.getRawValue();
        const toSnakeCase = (str: string) => str.replace(/[A-Z]/g, letter => `_${letter}`).toUpperCase();

        // =================================================================
        // ==== NOVA LOGIKA ZA ODREĐIVANJE TIPA SERTIFIKATA ================
        // =================================================================
        let certificateType: CertificateType;
        const isCaSelected = formValue.basicConstraints.isCa;

        if (this.isRootCertificate) {
          certificateType = 'ROOT';
        } else if (isCaSelected) {
          // Ako nije Root I izabrano je "Ovo je CA sertifikat"
          certificateType = 'INTERMEDIATE';
        } else {
          // Ako nije Root I NIJE izabrano "Ovo je CA sertifikat"
          certificateType = 'END_ENTITY';
        }
        // =================================================================


        const certificateDto = {
          commonName: formValue.commonName,
          organization: formValue.organization,
          organizationalUnit: formValue.organizationalUnit,
          country: formValue.country,
          email: formValue.email,
          validFrom: new Date(formValue.validFrom).toISOString(),
          validTo: new Date(formValue.validTo).toISOString(),
          issuerSerialNumber: this.isRootCertificate ? null : formValue.issuerSerialNumber,
          
          subjectUserId: subjectUserIdToSend,

          // NOVO: Dodavanje polja u DTO koje očekuje BE
          certificateType: certificateType, 
          
          keyUsages: Object.keys(formValue.keyUsage).filter(key => formValue.keyUsage[key]).map(key => toSnakeCase(key)),
          extendedKeyUsages: Object.keys(formValue.extendedKeyUsage).filter(key => formValue.extendedKeyUsage[key]).map(key => toSnakeCase(key)),
          subjectAlternativeNames: formValue.subjectAlternativeNames.map(
            (san: { type: string; value: string }) => `${san.type.toLowerCase()}:${san.value}`
          ),
        };
        
        console.log("FINALNI DTO koji se šalje na backend:", JSON.stringify(certificateDto, null, 2));

        const request = this.isRootCertificate
          ? this.certificateService.issueRootCertificate(certificateDto)
          : this.certificateService.issueCertificate(certificateDto);

        request.subscribe({
          next: (response) => {
            this.successMessage = 'Sertifikat je uspešno izdat!';
            this.isLoading = false;
            
            setTimeout(() => {
              this.successMessage = '';
              this.isRootCertificate = false;
              this.initForm(); 
              this.loadIssuers();
            }, 2500);
          },
          error: (error) => {
            this.errorMessage = error.error?.message || error.error || 'Došlo je do neočekivane greške.';
            this.isLoading = false;
            console.error('Greška pri izdavanju sertifikata:', error);
          }
        });
      },

      error: (err) => {
        this.errorMessage = "Greška pri dobavljanju podataka o korisniku. Proverite da li ste ulogovani.";
        this.isLoading = false;
        console.error('Greška pri pozivu fetchCurrentUserId:', err);
      }
    });
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