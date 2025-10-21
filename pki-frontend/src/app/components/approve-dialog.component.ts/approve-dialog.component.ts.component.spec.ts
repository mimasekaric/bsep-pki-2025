import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ApproveDialogComponentTsComponent } from './approve-dialog.component.ts.component';

describe('ApproveDialogComponentTsComponent', () => {
  let component: ApproveDialogComponentTsComponent;
  let fixture: ComponentFixture<ApproveDialogComponentTsComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ApproveDialogComponentTsComponent]
    });
    fixture = TestBed.createComponent(ApproveDialogComponentTsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
