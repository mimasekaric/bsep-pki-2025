import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PasswordManagerComponent } from './password-manage.component';

describe('PasswordManageComponent', () => {
  let component: PasswordManagerComponent;
  let fixture: ComponentFixture<PasswordManagerComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [PasswordManagerComponent]
    });
    fixture = TestBed.createComponent(PasswordManagerComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
