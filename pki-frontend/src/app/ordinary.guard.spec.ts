import { TestBed } from '@angular/core/testing';

import { OrdinaryGuard } from './ordinary.guard';

describe('OrdinaryGuard', () => {
  let guard: OrdinaryGuard;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    guard = TestBed.inject(OrdinaryGuard);
  });

  it('should be created', () => {
    expect(guard).toBeTruthy();
  });
});
