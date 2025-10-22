import { Component, OnInit } from '@angular/core';
import { CertificateService, CertificateDetailsDTO } from '../../services/certificate.service';
import { AuthService, User } from '../../services/auth.service';
import { Observable } from 'rxjs';
import { CrlService } from 'src/app/services/crl.service';
import { RevokationService } from 'src/app/services/revokation.service';
import { RevokeDialogComponent, RevokeDialogResult } from '../revoke-dialog/revoke-dialog.component';
import { MatDialog } from '@angular/material/dialog';

@Component({
  selector: 'app-certificate-list',
  templateUrl: './certificate-list.component.html',
  styleUrls: ['./certificate-list.component.css']
})
export class CertificateListComponent implements OnInit {
  certificates: CertificateDetailsDTO[] = [];
  currentUser: User | null = null;
  isLoading = true;
  errorMessage = '';
  pageTitle = 'Moji Sertifikati'; // Dinamički naslov
   isRevokeModalVisible = false;
  selectedCertForRevocation: CertificateDetailsDTO | null = null;
  revocationReason = '';

  constructor(
    private certificateService: CertificateService,
    private authService: AuthService,
    private revokationService: RevokationService,
    private crlService: CrlService,
    public dialog: MatDialog
  ) { }

  ngOnInit(): void {
    // Prvo dobijamo trenutnog korisnika
    this.currentUser = this.authService.getCurrentUser();
    
    if (this.currentUser) {
      this.loadCertificates();
    } else {
      this.errorMessage = 'Greška: Korisnik nije ulogovan.';
      this.isLoading = false;
    }
  }

  loadCertificates(): void {
    this.isLoading = true;
    this.errorMessage = '';
    
    let certificateObservable: Observable<CertificateDetailsDTO[]>;

    // === KLJUČNA LOGIKA ZA ODABIR METODE ===
    switch (this.currentUser?.role) {
      case 'ROLE_ADMIN':
        this.pageTitle = 'Svi Sertifikati u Sistemu';
        certificateObservable = this.certificateService.getAllCertificates();
        break;

      case 'ROLE_CA_USER':
        this.pageTitle = 'Moji Sertifikati';
        certificateObservable = this.certificateService.getChainForCaUser();
        break;
      
      default: // Običan korisnik
        this.pageTitle = 'Moji Sertifikati';
        certificateObservable = this.certificateService.getCertificatesForUser();
        break;
    }

    certificateObservable.subscribe({
      next: (data) => {
        this.certificates = data;
        this.isLoading = false;
      },
      error: (err) => {
        this.errorMessage = 'Greška pri učitavanju sertifikata.';
        this.isLoading = false;
      }
    });
  }

 downloadCertificate(certificateId: number): void {
    this.certificateService.downloadCertificate(certificateId).subscribe({
      next: (blob: Blob) => {
 
        const url = window.URL.createObjectURL(blob);
      
        const a = document.createElement('a');
        a.href = url;
        a.download = `certificate_${certificateId}.p7b`;
      
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
      
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Greška pri preuzimanju sertifikata:', err);
        alert('Došlo je do greške prilikom preuzimanja sertifikata.');
      }
    });
  }

   openRevokeDialog(cert: CertificateDetailsDTO): void {
    const dialogRef = this.dialog.open(RevokeDialogComponent, {
      width: '450px',
      data: { certificate: cert } // Prosleđujemo podatke u dijalog
    });

    dialogRef.afterClosed().subscribe((result: RevokeDialogResult) => {
      if (result && result.revoked && result.reason) {

        this.revokationService.revokeCertificate(cert.serialNumber, result.reason).subscribe({
          next: () => {
            alert(`Sertifikat ${cert.serialNumber} je uspešno povučen.`);
            this.loadCertificates(); 
          },
          error: (err) => {
      
          }
        });
      }
    });
  }
  


  downloadCrl(issuerSerial: string): void {
    this.crlService.downloadCrl(issuerSerial).subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${issuerSerial}.crl`; 
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Greška pri preuzimanju CRL-a:', err);
        alert('Greška prilikom preuzimanja CRL-a.');
      }
    });
  }
}