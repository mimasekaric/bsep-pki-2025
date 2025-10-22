import { TestBed } from '@angular/core/testing';

import { AedminOrCaGuard } from './aedmin-or-ca.guard';

describe('AedminOrCaGuard', () => {
  let guard: AedminOrCaGuard;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    guard = TestBed.inject(AedminOrCaGuard);
  });

  it('should be created', () => {
    expect(guard).toBeTruthy();
  });
});
