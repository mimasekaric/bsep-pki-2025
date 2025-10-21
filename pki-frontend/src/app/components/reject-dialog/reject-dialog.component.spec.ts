import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RejectDialogComponent } from './reject-dialog.component';

describe('RejectDialogComponent', () => {
  let component: RejectDialogComponent;
  let fixture: ComponentFixture<RejectDialogComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [RejectDialogComponent]
    });
    fixture = TestBed.createComponent(RejectDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
