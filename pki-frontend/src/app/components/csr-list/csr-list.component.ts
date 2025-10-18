import { Component, OnInit } from '@angular/core';
import { CsrService, CsrResponse } from '../../services/csr.service';

@Component({
  selector: 'app-csr-list',
  templateUrl: './csr-list.component.html',
  styleUrls: ['./csr-list.component.css']
})
export class CsrListComponent implements OnInit {
  pendingCsrs: CsrResponse[] = [];
  isLoading = true;
  errorMessage = '';

  selectedCsr: CsrResponse | null = null;
  rejectionReason = '';

  constructor(private csrService: CsrService) { }

  ngOnInit(): void {
    this.loadPendingCsrs();
  }

  loadPendingCsrs(): void {
    this.isLoading = true;
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

  onApprove(csr: CsrResponse): void {
    // Za approve, prosleđujemo podatke koje smo sačuvali u CSR entitetu
    const approvePayload = {
      issuerSerialNumber: csr.signingCertificateSerialNumber,
      validFrom: csr.requestedValidFrom,
      validTo: csr.requestedValidTo,
      // Ekstenzije se čitaju iz CSR-a na backendu, tako da ih ne šaljemo
      keyUsages: [],
      extendedKeyUsages: [],
      subjectAlternativeNames: []
    };

    this.csrService.approveCsr(csr.id, approvePayload).subscribe({
      next: () => {
        alert('CSR uspešno odobren!');
        this.loadPendingCsrs(); // Ponovo učitaj listu
      },
      error: (err) => alert(`Greška pri odobravanju: ${err.error.message}`)
    });
  }

  openRejectModal(csr: CsrResponse): void {
    this.selectedCsr = csr;
    this.rejectionReason = ''; // Resetuj polje
  }

  onReject(): void {
    if (!this.selectedCsr || !this.rejectionReason) return;

    const payload = { rejectionReason: this.rejectionReason };
    this.csrService.rejectCsr(this.selectedCsr.id, payload).subscribe({
      next: () => {
        alert('CSR uspešno odbijen!');
        this.selectedCsr = null; // Zatvori modal
        this.loadPendingCsrs(); // Ponovo učitaj listu
      },
      error: (err) => alert(`Greška pri odbijanju: ${err.error.message}`)
    });
  }
}