import { Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { CsrResponse } from 'src/app/services/csr.service';

export interface RejectDialogData {
  csr: CsrResponse;
}

export interface RejectDialogResult {
  rejected: boolean;
  reason?: string;
}

@Component({
  selector: 'app-reject-dialog',
  templateUrl: './reject-dialog.component.html',
  styleUrls: ['./reject-dialog.component.css']
})
export class RejectDialogComponent {
  rejectionReason = '';

  constructor(
    public dialogRef: MatDialogRef<RejectDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: RejectDialogData
  ) {}

  onCancel(): void {
    this.dialogRef.close({ rejected: false });
  }

  onConfirm(): void {
    if (!this.rejectionReason.trim()) return;
    this.dialogRef.close({
      rejected: true,
      reason: this.rejectionReason
    });
  }
}