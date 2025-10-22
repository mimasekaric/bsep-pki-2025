import { TestBed } from '@angular/core/testing';

import { CaGuard } from './ca.guard';

describe('CaGuard', () => {
  let guard: CaGuard;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    guard = TestBed.inject(CaGuard);
  });

  it('should be created', () => {
    expect(guard).toBeTruthy();
  });
});
