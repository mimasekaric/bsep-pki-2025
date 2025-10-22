// src/app/components/password-manager/password-manager.component.ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Subscription, BehaviorSubject, combineLatest, of, throwError } from 'rxjs';
import { switchMap, tap, catchError } from 'rxjs/operators';
import { PasswordManagerService } from 'src/app/services/password-manager.service';
import { CryptoService } from '../../services/crypto.service';
import { AuthService } from '../../services/auth.service'; // Za pristup korisničkim informacijama
import { CertificateService } from 'src/app/services/certificate.service';


export interface PasswordEntryDTO {
    id: string;
    siteName: string;
    username: string;
    ownerId: string; // UUID
    ownerUsername: string; // 
    createdAt: string; // LocalDateTime
    sharedWith: { [userId: string]: string }; // Mapa UUID-a i enkriptovanih lozinki
}

export interface PasswordEntryRequestDTO {
    siteName: string;
    username: string;
    encryptedPassword: string;
}

export interface SharePasswordDTO {
    shareWithUserName: string; // UUID
    reEncryptedPassword: string;
}

// src/app/dtos/user-dtos.ts
export interface UserCertificateDTO {
    userId: string; // UUID
    certificatePem: string; // CELI sertifikat u PEM formatu
    publicKeyPem: string; // Samo javni ključ iz sertifikata, ako ga backend može ekstrahovati
    // ... ostali podaci o sertifikatu
}

@Component({
  selector: 'app-password-manager',
  templateUrl: './password-manage.component.html',
  styleUrls: ['./password-manage.component.css']
})
export class PasswordManagerComponent implements OnInit, OnDestroy {
  passwordForm: FormGroup;
  shareForm: FormGroup;
  
  // Ključevi
  privateKey: CryptoKey | null = null;
  publicKey: CryptoKey | null = null; // Ovo je javni ključ trenutnog korisnika (vlasnika)
  
  // Prikaz podataka
  passwordEntries: PasswordEntryDTO[] = [];
  selectedPasswordEntry: PasswordEntryDTO | null = null;
  decryptedPassword: string = '';
  
  // UI stanje
  isLoading = false;
  errorMessage = '';
  successMessage = '';
  
  // Kontrola prikaza
  showCreateForm = false;
  showShareForm = false;

  // Subjekti za osvežavanje liste lozinki
  private refreshPasswordEntries$ = new BehaviorSubject<boolean>(true);
  private subscriptions: Subscription[] = [];

  constructor(
    private fb: FormBuilder,
    private passwordManagerService: PasswordManagerService,
    private cryptoService: CryptoService,
    private authService: AuthService,
    private certificatService:CertificateService
  ) {
    this.passwordForm = this.fb.group({
      siteName: ['', Validators.required],
      username: ['', Validators.required],
      plainTextPassword: ['', Validators.required] // Polje za unos plain-text lozinke
    });

    this.shareForm = this.fb.group({
       sharedWithUserId: ['', [
    Validators.required,
    
  ]]// UUID korisnika sa kojim se deli
      // encryptedSharedPassword se generiše programski
    });
  }
 isSharedWithCurrentUser(entry: PasswordEntryDTO): boolean {
    // Lozinka je podeljena sa trenutnim korisnikom ako on nije vlasnik
    // I ako postoji u `sharedWith` mapi sa njegovim emailom kao ključem
    // (ovo drugo je reduntantno ako backend vraća samo relevantne shared entries)
    return entry.ownerUsername !== this.authService.getCurrentUser()?.id;
  }
  isOwnedByCurrentUser(entry: PasswordEntryDTO): boolean {
    console.log("entry:", entry);
    console.log("owner id first and currentId second", entry.ownerUsername, this.authService.getCurrentUser()?.id );
    return entry.ownerUsername === this.authService.getCurrentUser()?.id;

  }
  ngOnInit(): void {

        this.loadUsersPublicKey()
    this.subscriptions.push(
      this.refreshPasswordEntries$.pipe(
        switchMap(() => this.passwordManagerService.getUserPasswordEntries())
      ).subscribe({
        next: (entries) => this.passwordEntries = entries,
        error: (err) => this.handleError(err, 'Greška pri učitavanju lozinki.')
      })
    );
  }

  ngOnDestroy(): void {
    this.subscriptions.forEach(sub => sub.unsubscribe());
  }

  // --- Upravljanje ključevima ---
  onPrivateKeyFileSelected(event: any): void {
    const file: File = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e: any) => {
        const pem = e.target.result;
        this.cryptoService.importPrivateKey(pem).subscribe({
          next: (key) => {
            this.privateKey = key;
            this.showSuccess('Privatni ključ uspešno učitan!');
          },
          error: (err) => this.handleError(err, 'Greška pri uvozu privatnog ključa.')
        });
      };
      reader.readAsText(file);
    }
  }

    loadUsersPublicKey(): void {
    this.isLoading = true;
    this.clearMessages();
    this.certificatService.getMyPublicKey().subscribe({
      next: (publicKeyPem: string) => {
        this.cryptoService.importPublicKey(publicKeyPem).subscribe({
          next: (key) => {
            this.publicKey = key;
            this.showSuccess('Vaš javni ključ je uspešno učitan sa servera!');
            this.isLoading = false;
          },
          error: (err) => this.handleError(err, 'Greška pri uvozu vašeg javnog ključa dobavljenog sa servera.')
        });
      },
      error: (err) => this.handleError(err, 'Greška pri dohvatanju vašeg javnog ključa sa servera. Proverite da li imate važeći End-Entity sertifikat.')
    });
  }



  // --- Kreiranje novog unosa lozinke ---
  createPasswordEntry(): void {
    if (this.passwordForm.invalid) {
      this.errorMessage = 'Molimo popunite sva obavezna polja.';
      return;
    }
    if (!this.publicKey) {
      this.errorMessage = 'Molimo prvo sacekajte  vas javni kljuc za enkripciju.';
      return;
    }

    this.isLoading = true;
    this.clearMessages();

    const plainTextPassword = this.passwordForm.get('plainTextPassword')?.value;

    this.cryptoService.encrypt(this.publicKey, plainTextPassword).pipe(
      switchMap(encryptedPass => {
        const dto: PasswordEntryRequestDTO = {
          siteName: this.passwordForm.get('siteName')?.value,
          username: this.passwordForm.get('username')?.value,
          encryptedPassword: encryptedPass
        };
        return this.passwordManagerService.createPasswordEntry(dto);
      })
    ).subscribe({
      next: (entry) => {
        this.showSuccess('Lozinka uspešno kreirana!');
        this.passwordForm.reset();
        this.refreshPasswordEntries$.next(true); // Osveži listu
        this.isLoading = false;
        this.showCreateForm = false;
      },
      error: (err) => this.handleError(err, 'Greška pri kreiranju lozinke.')
    });
  }

  // --- Odabir lozinke za pregled/dekripciju ---
  selectPasswordEntry(entry: PasswordEntryDTO): void {
    this.selectedPasswordEntry = entry;
    this.decryptedPassword = ''; // Resetuj prethodnu dekriptovanu lozinku
    this.showShareForm = false; // Sakrij formu za deljenje
    this.clearMessages();
  }

  // --- Dekripcija odabrane lozinke ---
  decryptSelectedPassword(): void {
    if (!this.selectedPasswordEntry) {
      this.errorMessage = 'Nijedna lozinka nije odabrana.';
      return;
    }
    if (!this.privateKey) {
      this.errorMessage = 'Molimo prvo ucitajte vas privatni kljuc za dekripciju.';
      return;
    }

    this.isLoading = true;
    this.clearMessages();

    // Dohvat enkriptovane lozinke specifične za trenutnog korisnika sa backenda
    this.passwordManagerService.getEncryptedPasswordForUser(this.selectedPasswordEntry.id!).pipe(
      switchMap(encryptedPassBase64 => {
        if (!encryptedPassBase64) {
          return throwError(() => new Error('Nema enkriptovane lozinke dostupne za dekripciju.'));
        }
        return this.cryptoService.decrypt(this.privateKey!, encryptedPassBase64);
      })
    ).subscribe({
      next: (decryptedPass) => {
        this.decryptedPassword = decryptedPass;
        this.showSuccess('Lozinka uspesno dekriptovana!');
        this.isLoading = false;
      },
      error: (err) => this.handleError(err, 'Greska pri dekripciji lozinke. Proverite kljuc.')
    });
  }
  sharePasswordEntry(): void {
    if (this.shareForm.invalid) {
      this.errorMessage = 'Molimo unesite validan ID korisnika (UUID) sa kojim delite.';
      return;
    }
    if (!this.selectedPasswordEntry) {
      this.errorMessage = 'Nijedna lozinka nije odabrana za deljenje.';
      return;
    }
    if (!this.privateKey) {
      this.errorMessage = 'Molimo prvo učitajte vaš privatni ključ da biste mogli da delite lozinke.';
      return;
    }

    this.isLoading = true;
    this.clearMessages();

    const sharedWithUserId = this.shareForm.get('sharedWithUserId')?.value;
    const selectedEntryId = this.selectedPasswordEntry.id;

    // KORAK 1: Dohvati *svoju* enkriptovanu lozinku za odabrani entry sa backenda
    this.passwordManagerService.getEncryptedPasswordForUser(selectedEntryId).pipe(
      switchMap(ownerEncryptedPassword => {
        if (!ownerEncryptedPassword) {
          return throwError(() => new Error('Originalna enkriptovana lozinka nije dostupna za deljenje.'));
        }
        // KORAK 2: Dekriptuj je svojim lokalno učitanim privatnim ključem (plaintext lozinka)
        return this.cryptoService.decrypt(this.privateKey!, ownerEncryptedPassword);
      }),
      switchMap(plainTextPassword => {
        // KORAK 3: Dohvati JAVNI KLJUČ KORISNIKA SA KOJIM SE DELI (sa backenda)
        return combineLatest([
          of(plainTextPassword),
          this.certificatService.getPublicKeyForUser(sharedWithUserId) // Nova frontend metoda
        ]);
      }),
      switchMap(([plainTextPassword, receiverPublicKeyPem]: [string, string]) => {
        // KORAK 4: Uvezi javni ključ primaoca u Web Crypto API format
        return combineLatest([
          of(plainTextPassword),
          this.cryptoService.importPublicKey(receiverPublicKeyPem)
        ]);
      }),
      switchMap(([plainTextPassword, receiverPublicKey]: [string, CryptoKey]) => {
        // KORAK 5: Enkriptuj plaintext lozinku javnim ključem primaoca
        return this.cryptoService.encrypt(receiverPublicKey, plainTextPassword);
      }),
      switchMap((reEncryptedPassword: string) => {
        // KORAK 6: Pošalji re-enkriptovanu lozinku (i ID primaoca) backendu
        const shareDto: SharePasswordDTO = {
          shareWithUserName:sharedWithUserId,
          reEncryptedPassword: reEncryptedPassword
        };
        return this.passwordManagerService.sharePasswordEntry(selectedEntryId, shareDto);
      })
    ).subscribe({
      next: (updatedEntry: PasswordEntryDTO) => {
        this.showSuccess('Lozinka uspešno podeljena!');
        this.shareForm.reset();
        this.refreshPasswordEntries$.next(true);
        this.isLoading = false;
        this.showShareForm = false;
        this.selectedPasswordEntry = updatedEntry;
      },
      error: (err: any) => this.handleError(err, 'Greška pri deljenju lozinke. Proverite ID korisnika i svoj privatni ključ.')
    });
  }

  // --- Brisanje lozinke ---
  deletePasswordEntry(id: String): void {
    this.isLoading = true;
    this.clearMessages();
    this.passwordManagerService.deletePasswordEntry(id).subscribe({
      next: () => {
        this.showSuccess('Lozinka uspešno obrisana!');
        this.refreshPasswordEntries$.next(true); // Osveži listu
        this.isLoading = false;
        this.selectedPasswordEntry = null; // Resetuj odabrani unos
        this.decryptedPassword = '';
      },
      error: (err: any)  => this.handleError(err, 'Greška pri brisanju lozinke.')
    });
  }


  // --- Pomoćne UI funkcije ---
  clearMessages(): void {
    this.errorMessage = '';
    this.successMessage = '';
  }

  showSuccess(message: string): void {
    this.clearMessages();
    this.successMessage = message;
  }

  handleError(error: any, defaultMessage: string): void {
    this.isLoading = false;
    this.errorMessage = error.error?.message || defaultMessage;
    console.error(error);
  }
}