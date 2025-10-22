import { Component, Inject, OnInit } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { CaCertificate, CsrResponse } from 'src/app/services/csr.service';
import { CertificateDetailsDTO, CertificateService } from 'src/app/services/certificate.service';

export interface ApproveDialogData {
  csr: CsrResponse;
}

export interface ApproveDialogResult {
  approved: boolean;
  signingCertSerial?: string;
}

@Component({
  selector: 'app-approve-dialog',
  templateUrl: './approve-dialog.component.ts.component.html',
  styleUrls: ['./approve-dialog.component.ts.component.css']
})
export class ApproveDialogComponent implements OnInit {
  availableSigningCerts: CertificateDetailsDTO[] = [];
  selectedSigningCertSerial = '';
  isLoading = true;
  errorMessage = '';

  constructor(
    public dialogRef: MatDialogRef<ApproveDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: ApproveDialogData,
    private certificateService: CertificateService
  ) {}

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.certificateService.getMyCaCertificates().subscribe({
      next: (certs) => {
        this.availableSigningCerts = certs;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju CA sertifikata.';
        this.isLoading = false;
      }
    });
  }

  onCancel(): void {
    this.dialogRef.close({ approved: false });
  }

  onConfirm(): void {
    if (!this.selectedSigningCertSerial) return;
    this.dialogRef.close({
      approved: true,
      signingCertSerial: this.selectedSigningCertSerial
    });
  }
}