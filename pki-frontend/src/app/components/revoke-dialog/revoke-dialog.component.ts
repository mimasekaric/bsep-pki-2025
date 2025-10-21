import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { CertificateDetailsDTO } from 'src/app/services/certificate.service';

// Definišemo kakve podatke dijalog prima
export interface RevokeDialogData {
  certificate: CertificateDetailsDTO;
}

// Definišemo kakav rezultat dijalog vraća
export interface RevokeDialogResult {
  revoked: boolean;
  reason?: string;
}

@Component({
  selector: 'app-revoke-dialog',
  templateUrl: './revoke-dialog.component.html',
  styleUrls: ['./revoke-dialog.component.css']
})
export class RevokeDialogComponent {
  
  reason = '';

  constructor(
    public dialogRef: MatDialogRef<RevokeDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: RevokeDialogData
  ) {}

  onCancel(): void {
    // Zatvori dijalog bez rezultata
    this.dialogRef.close({ revoked: false });
  }

  onConfirm(): void {
    // Zatvori dijalog i vrati rezultat
    if (!this.reason.trim()) return;
    this.dialogRef.close({ revoked: true, reason: this.reason });
  }
}