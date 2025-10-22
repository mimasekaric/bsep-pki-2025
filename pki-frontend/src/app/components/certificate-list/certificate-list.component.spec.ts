import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CertificateListComponent } from './certificate-list.component';

describe('CertificateListComponent', () => {
  let component: CertificateListComponent;
  let fixture: ComponentFixture<CertificateListComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CertificateListComponent]
    });
    fixture = TestBed.createComponent(CertificateListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
