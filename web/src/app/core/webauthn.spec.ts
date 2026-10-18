import { forTesting } from './webauthn';

const { fromBase64url, toBase64url } = forTesting;

describe('base64url', () => {
  it('round-trips every byte value', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    const encoded = toBase64url(bytes.buffer);

    expect(encoded).not.toMatch(/[+/=]/);
    expect(new Uint8Array(fromBase64url(encoded))).toEqual(bytes);
  });

  it('decodes unpadded input of any length', () => {
    for (const s of ['AQ', 'AQI', 'AQID', 'AQIDBA']) {
      expect(toBase64url(fromBase64url(s))).toBe(s);
    }
  });
});
