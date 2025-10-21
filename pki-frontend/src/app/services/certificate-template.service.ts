import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
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

@Injectable({
  providedIn: 'root'
})
export class CertificateTemplateService {
  private apiUrl = 'http://localhost:8080/api/templates'; // Prilagodite vašem backend URL-u

  constructor(private http: HttpClient) {}

  createTemplate(template: TemplateCreateDTO): Observable<any> {
    return this.http.post(`${this.apiUrl}`, template);
  }

  getTemplates(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}`);
  }

  getTemplateById(id: number): Observable<any> {
    return this.http.get(`${this.apiUrl}/${id}`);
  }

  deleteTemplate(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/${id}`);
  }
}
