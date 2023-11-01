import fs from 'fs';
import simpleCookie from 'simple-cookie';
import { sanitize } from '../src';
import { Har } from '../src/har';
import { version, name } from '../package.json';


const example = JSON.parse(fs.readFileSync('__test__/example.har', 'utf8')) as Har;

// push a form encoded copy of the latest entry
example.log.entries.push(
  {
    ...example.log.entries[2],
    request: {
      ...example.log.entries[2].request,
      postData: {
        ...example.log.entries[2].request.postData!,
        mimeType: 'application/x-www-form-urlencoded',
        text: 'username=foo&password=bar'
      }
    }
  }
);

example.log.entries.push(
  {
    ...example.log.entries[2],
    response: {
      ...example.log.entries[2].response,
      status: 201,
      content: {
        ...example.log.entries[2].response.content!,
        text: JSON.stringify({ access_token: '123', id_token: '456', code: 789 })
      }
    }
  }
);

describe('sanitizer', () => {
  let sanitized: Har;
  beforeAll(async () => {
    sanitized = await sanitize(example, { tokens: 'obfuscate' });
  });

  it('should obfuscate passwords from json request body', () => {
    expect(JSON.parse(sanitized.log.entries[2].request.postData!.text!).password)
      .toEqual('obfuscated');
  });

  it('should obfuscate passwords from form encoded request body', () => {
    expect(new URLSearchParams(sanitized.log.entries[3].request.postData!.text!).get('password'))
      .toEqual('obfuscated');
  });

  it('should obfuscate tokens in json response body', () => {
    const parsedResponse = JSON.parse(sanitized.log.entries[4].response.content!.text!);
    expect(parsedResponse.access_token)
      .toEqual('obfuscated');
    expect(parsedResponse.id_token)
      .toEqual('obfuscated');
    expect(parsedResponse.code)
      .toEqual('obfuscated');
  });

  it('should obfuscate bodies that are not json or form encoded', () => {
    expect(sanitized.log.entries[0].response.content!.text!).toEqual('obfuscated');
  });
});
