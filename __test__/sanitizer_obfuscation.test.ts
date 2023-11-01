import fs from 'fs';
import simpleCookie from 'simple-cookie';
import { sanitize } from '../src';
import { Har } from '../src/har';
import { version, name } from '../package.json';


const example = JSON.parse(fs.readFileSync('__test__/example.har', 'utf8')) as Har;

describe('sanitizer cookies obfuscation', () => {
  let sanitized: Har;
  beforeAll(async () => {
    sanitized = await sanitize(example, { salt: false, cookies: 'obfuscate', tokens: 'obfuscate' });
  });

  it('should sanitize set-cookie on responses', async () => {
    const actual = sanitized.log.entries[0].response.headers.find(h => h.name === 'set-cookie');
    const unsanitized = example.log.entries[0].response.headers.find(h => h.name === 'set-cookie');
    expect(actual).not.toEqual(unsanitized);
    const parsedActual = simpleCookie.parse(actual!.value);
    const parsedUnsanitized = simpleCookie.parse(unsanitized!.value);

    expect(parsedActual.value).toEqual('obfuscated');
    expect(parsedActual.domain).toEqual(parsedUnsanitized.domain);
    expect(parsedActual.path).toEqual(parsedUnsanitized.path);
    expect(parsedActual.expires).toEqual(parsedUnsanitized.expires);
    expect(parsedActual.secure).toEqual(parsedUnsanitized.secure);
  });

  it('should sanitize cookie on requests', async () => {
    const actual = sanitized.log.entries[0].request.headers.find(h => h.name === 'Cookie');
    const unsanitized = example.log.entries[0].request.headers.find(h => h.name === 'Cookie');
    expect(actual).not.toEqual(unsanitized);
    expect(actual!.value).toContain('obfuscated');
  });

  it('should sanitize cookies array on request', async () => {
    const actual = sanitized.log.entries[0].request.cookies;
    const unsanitized = example.log.entries[0].request.cookies;
    expect(actual).not.toEqual(unsanitized);
    expect(actual?.every(c => c.value === 'obfuscated')).toBeTruthy();
  });

  it('should sanitize cookies array on response', async () => {
    const actual = sanitized.log.entries[0].response.cookies;
    const unsanitized = example.log.entries[0].response.cookies;
    expect(actual).not.toEqual(unsanitized);
    expect(actual![0].value).toEqual('obfuscated');
  });

  it('should sanitize the authorization header', async () => {
    const actual = sanitized.log.entries[1].request.headers.find(h => h.name.toLowerCase() === 'authorization');
    const unsanitized = example.log.entries[1].request.headers.find(h => h.name.toLowerCase() === 'authorization');
    expect(actual).not.toEqual(unsanitized);
    expect(actual?.value).toEqual(`Bearer obfuscated`);
  });

});
