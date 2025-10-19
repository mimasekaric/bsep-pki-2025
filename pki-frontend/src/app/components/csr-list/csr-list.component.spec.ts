import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CsrListComponent } from './csr-list.component';

describe('CsrListComponent', () => {
  let component: CsrListComponent;
  let fixture: ComponentFixture<CsrListComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [CsrListComponent]
    });
    fixture = TestBed.createComponent(CsrListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
