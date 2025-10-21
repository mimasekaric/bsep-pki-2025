import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

// Kreiramo interfejs za tipizaciju podataka
export interface CertificateTemplate {
  id: number;
  templateName: string;
  issuerSerialNumber: string;
  commonNameRegex: string;
  sanRegex: string;
  ttlDays: number;
  keyUsage: string[];
  extendedKeyUsage: string[];
}

@Injectable({
  providedIn: 'root'
})
export class CertificateTemplateService {
  private readonly apiUrl = `$http://localhost:8080/api/templates`;

  constructor(private http: HttpClient) { }

  createTemplate(templateData: CertificateTemplate): Observable<string> { 
    return this.http.post(this.apiUrl, templateData, { responseType: 'text' });
  }
}