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
  reasonEntries = [
    { key: "unspecified", display: "Nespecifikovan razlog" },
    { key: "keyCompromise", display: "Kompromitovan ključ" },
    { key: "cACompromise", display: "Kompromitovan CA" },
    { key: "affiliationChanged", display: "Promenjena afilijacija" },
    { key: "superseded", display: "Zamenjen" },
    { key: "cessationOfOperation", display: "Prestanak rada" },
    { key: "certificateHold", display: "Zadržavanje sertifikata" },
    { key: "removeFromCRL", display: "Uklonjen iz CRL-a" },
    { key: "privilegeWithdrawn", display: "Oduzete privilegije" },
    { key: "aACompromise", display: "Kompromitovan AA" }
  ];
  reason = '';
 selectedReasonKey: string | null = null; 
  constructor(
    public dialogRef: MatDialogRef<RevokeDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: RevokeDialogData
  ) {}

  onCancel(): void {
    // Zatvori dijalog bez rezultata
    this.dialogRef.close({ revoked: false });
  }

  onConfirm(): void {
       if (!this.selectedReasonKey) return; // Proveravamo da li je razlog izabran

    // Konvertujemo izabrani ključ u odgovarajući numerički kod
    const reasonCode = this.selectedReasonKey;
    this.reason = this.selectedReasonKey;

    this.dialogRef.close({ revoked: true, reason: this.reason });
  }
}