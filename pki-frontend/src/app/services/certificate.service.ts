import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface CertificateIssueDTO {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  validFrom: string;
  validTo: string;
  issuerSerialNumber?: string;
  subjectUserId?: string;
}

export interface CertificateDetailsDTO {
  id: number;
  serialNumber: string;
  subjectDN: string;
  issuerSerialNumber: string;
  validFrom: string;
  validTo: string;
  type: string;
  revoked: boolean;
}

export interface IssuerDto {
  serialNumber: string;
  commonName: string;
  validFrom: string;
  validTo: string;
}

export interface CertificateWithPrivateKeyDTO {
  certificate: CertificateDetailsDTO;
  privateKeyPem: string;
}

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'http://localhost:8080/api/certificates';

  constructor(private http: HttpClient) { }

  issueRootCertificate(certificateData: CertificateIssueDTO): Observable<CertificateDetailsDTO> {
    return this.http.post<CertificateDetailsDTO>(`${this.apiUrl}/issue-root`, certificateData);
  }

  issueCertificate(certificateData: CertificateIssueDTO): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/issue`, certificateData);
  }

  getAvailableIssuers(): Observable<IssuerDto[]> {
    return this.http.get<IssuerDto[]>(`${this.apiUrl}/issuers`);
  }
}
