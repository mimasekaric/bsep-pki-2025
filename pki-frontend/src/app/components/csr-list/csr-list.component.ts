import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { CsrService, CsrResponse } from '../../services/csr.service';
import { ApproveDialogComponent, ApproveDialogResult } from '../approve-dialog.component.ts/approve-dialog.component.ts.component';
import { RejectDialogComponent, RejectDialogResult } from '../reject-dialog/reject-dialog.component';

@Component({
  selector: 'app-csr-list',
  templateUrl: './csr-list.component.html',
  styleUrls: ['./csr-list.component.css']
})
export class CsrListComponent implements OnInit {
  pendingCsrs: CsrResponse[] = [];
  isLoading = true;
  errorMessage = '';

  constructor(
    private csrService: CsrService,
    private dialog: MatDialog
  ) { }

  ngOnInit(): void {
    this.loadPendingCsrs();
  }

  loadPendingCsrs(): void {
    this.isLoading = true;
    this.errorMessage = '';
    this.csrService.getPendingCsrs().subscribe({
      next: (data) => {
        this.pendingCsrs = data;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju CSR zahteva.';
        this.isLoading = false;
      }
    });
  }

  openApproveDialog(csr: CsrResponse): void {
    const dialogRef = this.dialog.open(ApproveDialogComponent, {
      width: '600px',
      maxHeight: '90vh',
      data: { csr },
      disableClose: false,
      autoFocus: true,
      panelClass: 'centered-dialog'
    });

    dialogRef.afterClosed().subscribe((result: ApproveDialogResult) => {
      if (result && result.approved && result.signingCertSerial) {
        const payload = { signingCertificateSerialNumber: result.signingCertSerial };
        this.csrService.approveCsr(csr.id, payload).subscribe({
          next: () => {
            alert('CSR uspešno odobren!');
            this.loadPendingCsrs();
          },
          error: (err) => {
            alert(`Greška pri odobravanju: ${err.error?.message || 'Nepoznata greška'}`);
          }
        });
      }
    });
  }

  openRejectDialog(csr: CsrResponse): void {
  const dialogRef = this.dialog.open(RejectDialogComponent, {
    width: '500px',
    maxHeight: '90vh',
    data: { csr },
    disableClose: false,
    autoFocus: true,
    panelClass: 'centered-dialog'
  });

  dialogRef.afterClosed().subscribe((result: RejectDialogResult) => {
    if (result && result.rejected && result.reason) {
      const payload = { rejectionReason: result.reason };
      this.csrService.rejectCsr(csr.id, payload).subscribe({
        next: () => {
          alert('CSR uspešno odbijen!');
          this.loadPendingCsrs();
        },
        error: (err) => {
          alert(`Greška: ${err.error?.message || 'Nepoznata greška'}`);
        }
      });
    }
  });
  }
}