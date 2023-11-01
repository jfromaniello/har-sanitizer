import fs from 'fs';
import simpleCookie from 'simple-cookie';
import { sanitize } from '../src';
import { Har } from '../src/har';
import { version, name } from '../package.json';


const example = JSON.parse(fs.readFileSync('__test__/example.har', 'utf8')) as Har;

example.log.entries.push(
  {
    ...example.log.entries[0],
    request: {
      ...example.log.entries[0].request,
      url: "https://example.com/foobar?token=footoken",
      headers: [
        {
          name: 'Referer',
          value: "https://example.com/foobar?token=footoken"
        }
      ]
    },
    response: {
      ...example.log.entries[0].response,
      headers: [
        {
          name: 'Location',
          value: "https://example.com/foobar?token=footoken"
        }
      ]
    }
  }
);

describe('sanitizer', () => {
  let sanitized: Har;
  beforeAll(async () => {
    sanitized = await sanitize(example, { tokens: 'obfuscate' });
  });

  it('should obfuscate fields from query string', () => {
    const { searchParams: query } = new URL(sanitized.log.entries[3].request.url);
    expect(query.get('token')).toEqual('obfuscated');
  });

  it('should obfuscate fields from referer header', () => {
    const { searchParams: query } = new URL(sanitized.log.entries[3].request.headers.find(h => h.name === 'Referer')!.value);
    expect(query.get('token')).toEqual('obfuscated');
  });

  it('should obfuscate fields from the location header', () => {
    const { searchParams: query } = new URL(sanitized.log.entries[3].response.headers.find(h => h.name === 'Location')!.value);
    expect(query.get('token')).toEqual('obfuscated');
  });

});
