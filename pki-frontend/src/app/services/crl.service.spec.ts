import { TestBed } from '@angular/core/testing';

import { CrlService } from './crl.service';

describe('CrlService', () => {
  let service: CrlService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CrlService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
