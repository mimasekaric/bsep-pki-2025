// issue-certificate.component.ts

import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormArray } from '@angular/forms';
import { Router } from '@angular/router';
import { CertificateService, IssuerDto } from '../../services/certificate.service';
import { AuthService, User } from 'src/app/services/auth.service';
import { from, Subscription } from 'rxjs';
import { CertificateTemplateService, TemplateInfoDTO } from '../../services/template.service';

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
  isTemplateModalVisible = false;

  availableIssuers: IssuerDto[] = []; 

  issuerValidFrom: string = '';
  issuerValidTo: string = '';
  issuerValidFromDate: Date | null = null;
  issuerValidToDate: Date | null = null;
  isCaUser = false;

  private currentUserId: number | null = null;
  private userSubscription: Subscription;

  myTemplates: TemplateInfoDTO[] = [];
  selectedTemplate: TemplateInfoDTO | null = null;

  private keyUsageMap: { [key: string]: string } = {
    DIGITAL_SIGNATURE: 'digitalSignature',
    NON_REPUDIATION: 'nonRepudiation',
    KEY_ENCIPHERMENT: 'keyEncipherment',
    DATA_ENCIPHERMENT: 'dataEncipherment',
    KEY_AGREEMENT: 'keyAgreement',
    KEY_CERT_SIGN: 'keyCertSign',
    CRL_SIGN: 'crlSign'
  };

  private extendedKeyUsageMap: { [key: string]: string } = {
    SERVER_AUTH: 'serverAuth',
    CLIENT_AUTH: 'clientAuth',
    CODE_SIGNING: 'codeSigning',
    EMAIL_PROTECTION: 'emailProtection',
    TIME_STAMPING: 'timeStamping'
  };

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    private router: Router,
    private authService: AuthService,
    private templateService: CertificateTemplateService
  ) {
    this.certificateForm = this.fb.group({});
    this.userSubscription = this.authService.currentUser$.subscribe(user => {
      if (user && user.id) {
        this.currentUserId = user.id;
      } else {
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
    const currentUser = this.authService.getCurrentUser();
    
    if (!currentUser) {
        this.router.navigate(['/login']); 
        return;
    }

    const userRole = currentUser.role;

    if (userRole === 'ROLE_ORDINARY_USER') {
      alert("Kao običan korisnik ne možete pristupati stranici za izdavanje sertifikata."); 
      this.router.navigate(['/']); 
      return;
    } else if (userRole === 'ROLE_CA_USER') { 
      this.isCaUser = true;
      this.loadMyTemplates();
    }
    
    this.initForm();
    this.loadIssuers(); 
  }

  loadMyTemplates(): void {
    this.templateService.getMyTemplates().subscribe({
        next: (templates) => {
            this.myTemplates = templates;
            console.log("Uspešno učitani šabloni:", this.myTemplates);
        },
        error: (err) => {
            console.error("Greška pri učitavanju šablona:", err);
        }
    });
  }


  
  resetFormToEditable(): void {
    const currentValues = this.certificateForm.getRawValue();
    
    this.certificateForm.enable();
    this.certificateForm.get('commonName')?.setValidators([Validators.required]);
    this.certificateForm.get('commonName')?.updateValueAndValidity();

    this.certificateForm.get('keyUsage')?.reset();
    this.certificateForm.get('extendedKeyUsage')?.reset();
    

    if(this.isCaUser) {
      this.isRootCertificate = false;
    }
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
    if (this.isRootCertificate && this.isCaUser) {
        this.isRootCertificate = false; 
        alert("Kao CA korisnik nemate dozvolu za izdavanje Root sertifikata.");
    }

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
          return;
        }

        const subjectUserIdToSend = userWithId.id.toString();
        const formValue = this.certificateForm.getRawValue();
        const toSnakeCase = (str: string) => str.replace(/[A-Z]/g, letter => `_${letter}`).toUpperCase();

        let certificateType: CertificateType;
        const isCaSelected = formValue.basicConstraints.isCa;

        if (this.isRootCertificate) {
          certificateType = 'ROOT';
        } else if (isCaSelected) {
          certificateType = 'INTERMEDIATE';
        } else {
          certificateType = 'END_ENTITY';
        }

        const certificateDto = {
          templateId: this.selectedTemplate ? this.selectedTemplate.id : null,
          commonName: formValue.commonName,
          organization: formValue.organization,
          organizationalUnit: formValue.organizationalUnit,
          country: formValue.country,
          email: formValue.email,
          validFrom: new Date(formValue.validFrom).toISOString(),
          validTo: new Date(formValue.validTo).toISOString(),
          issuerSerialNumber: this.isRootCertificate ? null : formValue.issuerSerialNumber,
          subjectUserId: subjectUserIdToSend,
          certificateType: certificateType, 
          keyUsages: Object.keys(formValue.keyUsage).filter(key => formValue.keyUsage[key]).map(key => toSnakeCase(key)),
          extendedKeyUsages: Object.keys(formValue.extendedKeyUsage).filter(key => formValue.extendedKeyUsage[key]).map(key => toSnakeCase(key)),
          subjectAlternativeNames: formValue.subjectAlternativeNames.map(
            (san: { type: string; value: string }) => `${san.type.toLowerCase()}:${san.value}`
          ),
        };
        
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
          }
        });
      },
      error: (err) => {
        this.errorMessage = "Greška pri dobavljanju podataka o korisniku. Proverite da li ste ulogovani.";
        this.isLoading = false;
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

  openTemplateModal(): void {
    this.isTemplateModalVisible = true;
  }

  closeTemplateModal(): void {
    this.isTemplateModalVisible = false;
  }

  onTemplateSelectedFromModal(template: TemplateInfoDTO): void {
    this.selectedTemplate = template;
    console.log("Šablon izabran iz modala:", template);
    
    if (this.selectedTemplate) {
      this.applyTemplate(this.selectedTemplate);
    }

    this.closeTemplateModal();
  }

  clearTemplateSelection(): void {
    this.selectedTemplate = null;
    this.resetFormToEditable();
    console.log("Izbor šablona je poništen.");
  }

  applyTemplate(template: TemplateInfoDTO): void {
    // 1. Resetujemo formu na početno stanje
    this.resetFormToEditable();

    // --- NOVO: Postavljanje Izdavaoca (Issuer) ---
    if (template.issuerSerialNumber) {
        const issuerControl = this.certificateForm.get('issuerSerialNumber');
        
        // Pronalazimo izdavaoca u listi dostupnih
        const selectedIssuer = this.availableIssuers.find(i => i.serialNumber === template.issuerSerialNumber);
        
        if (selectedIssuer) {
            // Postavljamo vrednost u formu
            issuerControl?.setValue(selectedIssuer.serialNumber);
            issuerControl?.disable(); // Zaključavamo polje

            // Ažuriramo datume važenja (kopirano iz logike onIssuerChange)
            this.issuerValidFromDate = new Date(selectedIssuer.validFrom);
            this.issuerValidToDate = new Date(selectedIssuer.validTo);
            this.issuerValidFrom = this.formatDateForInput(this.issuerValidFromDate);
            this.issuerValidTo = this.formatDateForInput(this.issuerValidToDate);
        } else {
            console.warn(`Izdavalac sa serijskim brojem ${template.issuerSerialNumber} nije pronađen u listi dostupnih.`);
        }
    }
    // ---------------------------------------------

    // 2. Postavljamo validatore za Common Name
    if (template.commonNameRegex) {
      this.certificateForm.get('commonName')?.setValidators([Validators.required, Validators.pattern(template.commonNameRegex)]);
      this.certificateForm.get('commonName')?.updateValueAndValidity();
    }

    // 3. Postavljamo i zaključavamo TTL (period važenja)
    if (template.ttlDays) {
        const validFromControl = this.certificateForm.get('validFrom');
        const validToControl = this.certificateForm.get('validTo');
        
        // Uzimamo trenutnu vrednost 'validFrom' (koja je po defaultu 'danas')
        const fromDate = new Date(validFromControl?.value);
        const toDate = new Date(fromDate.getTime());
        toDate.setDate(fromDate.getDate() + template.ttlDays);

        // Provera da li izračunati datum izlazi van opsega izdavaoca
        if (this.issuerValidToDate && toDate > this.issuerValidToDate) {
             // Ako izlazi, postavljamo na maksimalni mogući datum izdavaoca
             validToControl?.setValue(this.formatDateForInput(this.issuerValidToDate));
        } else {
             validToControl?.setValue(this.formatDateForInput(toDate));
        }
        
        validToControl?.disable();
    }

    // 4. Postavljamo i zaključavamo Key Usage
    const keyUsageGroup = this.certificateForm.get('keyUsage') as FormGroup;
    for (const backendKey of template.keyUsage) {
      const formKey = this.keyUsageMap[backendKey];
      if (formKey) {
        keyUsageGroup.get(formKey)?.setValue(true);
        keyUsageGroup.get(formKey)?.disable();
      }
    }

    // 5. Postavljamo i zaključavamo Extended Key Usage
    const extendedKeyUsageGroup = this.certificateForm.get('extendedKeyUsage') as FormGroup;
    for (const backendKey of template.extendedKeyUsage) {
        const formKey = this.extendedKeyUsageMap[backendKey];
        if (formKey) {
            extendedKeyUsageGroup.get(formKey)?.setValue(true);
            extendedKeyUsageGroup.get(formKey)?.disable();
        }
    }
  }
}