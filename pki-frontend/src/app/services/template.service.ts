import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

export interface TemplateCreateDTO {
  templateName: string;
  issuerSerialNumber: string;
  commonNameRegex: string;
  sanRegex: string;
  ttlDays: number;
  keyUsage: string[];
  extendedKeyUsage: string[];
}

export interface TemplateInfoDTO {
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
  private readonly apiUrl = `https://localhost:8443/api/templates`;

  constructor(private http: HttpClient) { }

  createTemplate(templateData: TemplateCreateDTO): Observable<string> { 
    return this.http.post(this.apiUrl, templateData, { responseType: 'text' });
  }

  getMyTemplates(): Observable<TemplateInfoDTO[]> {
    return this.http.get<TemplateInfoDTO[]>(`${this.apiUrl}/my-templates`);
  }

  getTemplatesByIssuer(issuerSerialNumber: string): Observable<TemplateInfoDTO[]> {
    return this.http.get<TemplateInfoDTO[]>(`${this.apiUrl}/issuer/${issuerSerialNumber}`);
  }
}