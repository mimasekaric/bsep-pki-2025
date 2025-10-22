import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormArray } from '@angular/forms';
import { Router } from '@angular/router';
import { CertificateTemplateService, TemplateCreateDTO } from '../../services/template.service';
import { CertificateService, IssuerDto } from '../../services/certificate.service';
@Component({
  selector: 'app-template',
  templateUrl: './template.component.html',
  styleUrls: ['./template.component.css']
})
export class TemplateComponent implements OnInit {

  templateForm!: FormGroup;
  availableIssuers: IssuerDto[] = []; 
  isLoading = false;
  errorMessage: string | null = null;
  successMessage: string | null = null;

  keyUsageOptions = [
    { key: 'DIGITAL_SIGNATURE', label: 'Digital Signature' },
    { key: 'NON_REPUDIATION', label: 'Non Repudiation' },
    { key: 'KEY_ENCIPHERMENT', label: 'Key Encipherment' },
    { key: 'DATA_ENCIPHERMENT', label: 'Data Encipherment' },
    { key: 'KEY_AGREEMENT', label: 'Key Agreement' },
    { key: 'KEY_CERT_SIGN', label: 'Certificate Signing' },
    { key: 'CRL_SIGN', label: 'CRL Signing' }
  ];

  extendedKeyUsageOptions = [
    { key: 'SERVER_AUTH', label: 'TLS Web Server Authentication' },
    { key: 'CLIENT_AUTH', label: 'TLS Web Client Authentication' },
    { key: 'CODE_SIGNING', label: 'Code Signing' },
    { key: 'EMAIL_PROTECTION', label: 'Email Protection' }
  ];

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService, // Vaš postojeći servis
    private templateService: CertificateTemplateService, // Novi servis
    private router: Router
  ) {}

  ngOnInit(): void {
    this.initForm();
    this.loadIssuers();
  }

  initForm(): void {
    this.templateForm = this.fb.group({
      templateName: ['', [Validators.required, Validators.maxLength(50)]],
      issuerSerialNumber: [null, [Validators.required]],
      commonNameRegex: [''],
      sanRegex: [''],
      ttlDays: [365, [Validators.required, Validators.min(1)]],
      keyUsage: this.fb.array(this.keyUsageOptions.map(() => this.fb.control(false))),
      extendedKeyUsage: this.fb.array(this.extendedKeyUsageOptions.map(() => this.fb.control(false)))
    });
  }

  loadIssuers(): void {
    // ISPRAVKA: Pozivamo tačnu metodu iz vašeg servisa
    this.certificateService.getAvailableIssuers().subscribe({
      next: (issuers) => {
        this.availableIssuers = issuers;
      },
      error: (err: any) => {
        this.errorMessage = 'Greška pri učitavanju dostupnih izdavaoca.';
        console.error(err);
      }
    });
  }

  get keyUsageControls() {
    return (this.templateForm.get('keyUsage') as FormArray).controls;
  }

  get extendedKeyUsageControls() {
    return (this.templateForm.get('extendedKeyUsage') as FormArray).controls;
  }

  onSubmit(): void {
  this.errorMessage = null;
  this.successMessage = null;
  
  if (this.templateForm.invalid) {
    this.templateForm.markAllAsTouched();
    return;
  }

  this.isLoading = true;
  const rawValue = this.templateForm.getRawValue();

  const payload: TemplateCreateDTO = {
    templateName: rawValue.templateName,
    issuerSerialNumber: rawValue.issuerSerialNumber,
    commonNameRegex: rawValue.commonNameRegex,
    sanRegex: rawValue.sanRegex,
    ttlDays: rawValue.ttlDays,
    keyUsage: this.getSelectedValues(rawValue.keyUsage, this.keyUsageOptions),
    extendedKeyUsage: this.getSelectedValues(rawValue.extendedKeyUsage, this.extendedKeyUsageOptions)
  };
  
  this.templateService.createTemplate(payload).subscribe({
    next: (response: string) => { 
      this.isLoading = false;
      this.successMessage = response; 
      this.templateForm.reset({ ttlDays: 365 });
    },
    error: (err: any) => {
      this.isLoading = false;
      if (err.status === 201 && err.error?.text) {
        this.successMessage = err.error.text;
      } else {
        // Provera da li je greška zbog duplikata imena šablona
        const errorText = err.error?.message || err.error || '';
        if (errorText.includes('already exists') || errorText.includes('Template with name')) {
          this.errorMessage = 'Šablon sa ovim imenom već postoji. Molimo koristite jedinstveno ime za novi šablon.';
        } else {
          this.errorMessage = errorText || 'Došlo je do greške prilikom kreiranja šablona.';
        }
      }
      console.error(err);
    }
  });
}

  private getSelectedValues(formArrayValues: boolean[], options: { key: string }[]): string[] {
    return formArrayValues
      .map((checked, i) => checked ? options[i].key : null)
      .filter((value): value is string => value !== null);
  }

  hasError(controlName: string): boolean {
    const control = this.templateForm.get(controlName);
    return !!control && control.invalid && (control.dirty || control.touched);
  }

  getErrorMessage(controlName: string): string {
    const control = this.templateForm.get(controlName);
    if (control?.hasError('required')) return 'Ovo polje je obavezno.';
    if (control?.hasError('min')) return `Minimalna vrednost je ${control.errors?.['min'].min}.`;
    return '';
  }
}