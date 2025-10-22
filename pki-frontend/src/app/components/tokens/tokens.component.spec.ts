import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TokensComponent } from './tokens.component';

describe('TokensComponent', () => {
  let component: TokensComponent;
  let fixture: ComponentFixture<TokensComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [TokensComponent]
    });
    fixture = TestBed.createComponent(TokensComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
