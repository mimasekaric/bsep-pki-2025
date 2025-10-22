import { TestBed } from '@angular/core/testing';

import { RevokationService } from './revokation.service';

describe('RevokationService', () => {
  let service: RevokationService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(RevokationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
