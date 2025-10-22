import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CsrUploadComponent } from './csr-upload.component';

describe('CsrUploadComponent', () => {
  let component: CsrUploadComponent;
  let fixture: ComponentFixture<CsrUploadComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CsrUploadComponent]
    });
    fixture = TestBed.createComponent(CsrUploadComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
