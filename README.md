<p align="center">
  <img src="screenshots/Logo.png" alt="PKI System Logo" height="120" style="filter: drop-shadow(0 0 8px rgba(160, 100, 255, 0.6));"/>
</p>

**PKI System** je backend aplikacija za upravljanje digitalnim sertifikatima (Public Key Infrastructure), razvijena u **Spring Boot-u 3+** uz striktno poštovanje principa čiste arhitekture i jedinstvene odgovornosti svakog sloja.  
Sistem omogućava centralizovano izdavanje, validaciju i povlačenje digitalnih sertifikata, kao i bezbedno čuvanje i deljenje lozinki putem integrisanog password managera zasnovanog na javnim i privatnim ključevima.

> *Aplikacija je razvijena kao univerzitetski projekat, ali je u potpunosti funkcionalna i spremna za upotrebu.*

---

## Tehnološki stek

- **Backend:** Spring Boot 3+ (Java 17+)  
- **Baza podataka:** PostgreSQL  
- **ORM:** Spring Data JPA  
- **Bezbednost:** Spring Security  
- **Kriptografija:** Bouncy Castle  
- **Format keystore-a:** PKCS#12 (`.p12`)

---

## Arhitektura projekta

Projekat je organizovan po principu slojevite arhitekture sa jasnim granicama između slojeva:
controller → service → repository → domain


### Domain sloj
- JPA entiteti: `User`, `Certificate`, `Keystore`, `CSR`  
- Predstavlja model podataka koji se čuva u bazi

### Repository sloj
- Spring Data JPA repozitorijumi  
- Bez poslovne logike ili transformacija podataka

### Controller sloj
- REST kontroleri koji primaju i vraćaju DTO objekte  
- Pozivaju isključivo metode `CertificateService` servisa

### Service sloj (ključni deo sistema)
Servisni sloj je podeljen na jasno definisane servise sa jednom odgovornošću:

| Servis | Odgovornost |
|--------|--------------|
| **CertificateService** | Glavni orkestrator procesa izdavanja, validacije i povlačenja sertifikata. |
| **KeystoreService** | Upravljanje `.p12` keystore fajlovima (učitavanje, čuvanje, pristup ključevima). |
| **CryptoService** | Kriptografske operacije: generisanje ključeva, AES enkripcija/dekripcija. |
| **CertificateFactory** | Kreiranje X.509 sertifikata pomoću Bouncy Castle biblioteke. |
| **CrlService** | Generisanje i održavanje CRL (Certificate Revocation List) fajlova. |
| **CsrService** | Parsiranje i validacija CSR (Certificate Signing Request) fajlova. |

---

## Ključni koncepti

### Upravljanje keystore-om
- Svaki **Root CA** pokreće novi lanac poverenja i dobija jedinstveni `.p12` keystore fajl.  
- Lozinka za keystore se generiše nasumično, enkriptuje **master AES ključem** i čuva u bazi.

### Izdavanje sertifikata
- **Root sertifikat:** samopotpisani sertifikat koji inicira novi lanac poverenja.  
- **Intermediate/End-Entity sertifikati:** potpisani od strane postojećeg CA sertifikata.  
- Proces uključuje validaciju, generisanje ključeva, kreiranje X.509 sertifikata i čuvanje u keystore fajl.

### Povlačenje sertifikata
- Sertifikati se označavaju kao povučeni (`revoked = true`).  
- Ako je povučeni sertifikat CA tipa, povlače se i svi sertifikati koje je izdao.  
- Nakon povlačenja, sistem regeneriše odgovarajući CRL fajl.

---

## Korisničke uloge

| Uloga | Opis i prava |
|--------|---------------|
| **Administrator** | Dodaje CA korisnike, izdaje sve tipove sertifikata, vidi sve sertifikate i upravlja revokacijom. |
| **CA korisnik** | Izdaje intermediate i end-entity sertifikate unutar svog lanca, kreira šablone i pregleda svoje sertifikate. |
| **Običan korisnik** | Uploaduje CSR fajlove, preuzima izdate sertifikate, vrši revokaciju sopstvenih sertifikata. |

---

## Funkcionalnosti sistema

### Autentifikacija i autorizacija
- Registracija putem emaila sa aktivacionim linkom (vremenski ograničen)  
- Prijava uz reCAPTCHA validaciju  
- Oporavak naloga putem email linka  
- Pregled i opoziv aktivnih JWT tokena (upravljanje sesijama po uređajima)

### Upravljanje sertifikatima
- Izdavanje Root, Intermediate i End-Entity sertifikata  
- Validacija perioda važenja i potpisa izdavaoca  
- Čuvanje CA sertifikata i ključeva u keystore fajlovima  
- EE sertifikati se čuvaju bez privatnih ključeva

### CSR (Certificate Signing Request)
- Upload eksternog `.pem` fajla  
- Odabir CA sertifikata za potpisivanje  
- Validacija trajanja i ekstenzija sertifikata  

### Revokacija (povlačenje)
- Povlačenje sertifikata uz obavezno navođenje razloga prema X.509 standardu  
- Povučeni sertifikati se isključuju iz daljeg izdavanja  
- Automatsko generisanje i ažuriranje CRL fajlova

---

## Šabloni za sertifikate (Certificate Templates)

CA korisnici mogu definisati šablone koji pojednostavljuju proces izdavanja:

- Naziv šablona  
- CA issuer  
- Regex validacija za CN i SAN  
- TTL (vreme važenja)  
- Key Usage i Extended Key Usage vrednosti  

Šabloni omogućavaju dosledno pridržavanje politika sertifikata unutar organizacije.

---

## Password Manager funkcionalnost

Integrisani password manager omogućava bezbedno čuvanje i deljenje poverljivih informacija korišćenjem javnih i privatnih ključeva korisnika.

- Lozinke se enkriptuju **javnim ključem korisnika**  
- Dekripcija se obavlja **lokalno** (na klijentskoj strani) pomoću privatnog ključa  
- Server nikada ne čuva privatne ključeve korisnika

### Deljenje lozinki
- Lozinka se dešifruje lokalno i ponovo enkriptuje javnim ključem korisnika sa kojim se deli  
- Backend čuva više verzija iste lozinke, enkriptovane za različite korisnike

Primer strukture zapisa u bazi:

```json
{
  "entry": {
    "id": 1,
    "site_name": "Gmail",
    "username": "alice2000",
    "owner_id": 1
  },
  "shares": [
    { "user_id": 1, "encrypted_password": "MIIBIjANBgkqhkiG9w0BAQEFA..." },
    { "user_id": 2, "encrypted_password": "MIIBIjANBgkqhkiG9w0BAQEFG..." }
  ]
} 
```

---
## Bezbednost i zaštita
* HTTPS komunikacija između svih servisa
* Višefaktorska autentifikacija (MFA)
* Audit logovi sa rotacijom log fajlova
* Zaštita od poznatih ranjivosti:
 * SQL Injection
 * XSS (Cross-Site Scripting)
 * CSRF
* Validacija i sanitizacija korisničkog inputa na svim nivoima

## Logging i audit mehanizam
- Beleži sve događaje od bezbednosnog značaja
- Standardizovan format loga
- Mehanizam za rotaciju i arhiviranje logova
- Cilj: pouzdanost, upotrebljivost i neporecivost zapisa

## Instalacija i pokretanje

### 1. Kloniranje repozitorijuma
```bash
git clone https://github.com/yourusername/pki-system.git
cd pki-system
```

