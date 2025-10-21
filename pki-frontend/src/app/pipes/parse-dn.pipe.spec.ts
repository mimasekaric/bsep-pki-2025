import { ParseDnPipe } from './parse-dn.pipe';

describe('ParseDnPipe', () => {
  it('create an instance', () => {
    const pipe = new ParseDnPipe();
    expect(pipe).toBeTruthy();
  });
});
