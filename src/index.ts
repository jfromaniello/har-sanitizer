import simpleCookie from "simple-cookie";
import { Har, HarEntry, HarHeader } from "./har";
import { getSHA256Hash, getSalt } from "./util";
import { name as pkgName, version as pkgVersion } from "../package.json";

type SanitizationType = 'hash' | 'obfuscate';

/**
 * Sanitize options
 */
export type SanitizeOptions = {
  /**
   * If true, salt will be added when hashing.
   */
  salt: boolean;

  /**
   * How to sanitize cookies. Defaults to `hash`.
   * - `obfuscate`: will replace the value of the cookie with a single string obfuscated.
   * - `hash`: will replace the value of the cookie with a SHA256 hash of the original value.
   */
  cookies: SanitizationType;

  /**
   * How to sanitize tokens. Defaults to `hash`.
   * - `obfuscate`: will replace the value of the token with a single string obfuscated.
   * - `hash`: will replace the value of the token with a SHA256 hash of the original value.
   */
  tokens: SanitizationType;
};

const defaultOptions: SanitizeOptions = {
  salt: true,
  cookies: 'hash',
  tokens: 'hash'
};

async function sanitizeAuthorizationHeader(h: HarHeader, salt: string, type: SanitizationType) {
  const [scheme, value] = h.value.split(/\s(.+)/);
  const hashed = type === 'obfuscate' ?
    'obfuscated' :
    await getSHA256Hash(salt, value);
  return { ...h, value: `${scheme} ${hashed}` };
}

async function sanitizeRequestCookieHeader(h: HarHeader, salt: string, type: SanitizationType) {
  const result = await Promise.all(h.value.split(/;\s?/g).map(async (s) => {
    const [name, value] = s.split(/=(.*)/);
    const hashed = type === 'obfuscate' ?
      'obfuscated' :
      await getSHA256Hash(salt, value);
    return `${name}=${hashed}`;
  }));
  const value = result.join('; ') + ';';
  return { ...h, value };
}

async function sanitizeResponseSetCookie(h: HarHeader, salt: string, type: SanitizationType) {
  const cookie = simpleCookie.parse(h.value);
  cookie.value = type === 'obfuscate' ?
    'obfuscated' :
    await getSHA256Hash(salt, cookie.value);
  const value = simpleCookie.stringify(cookie);
  return { ...h, value };
}

const sanitizeEntry = async (entry: HarEntry, salt: string, options: SanitizeOptions): Promise<HarEntry> => {
  const responseHeaders = await Promise.all(entry.response.headers.map(async h => {
    if (h.name.toLowerCase() === 'set-cookie') {
      return await sanitizeResponseSetCookie(h, salt, options.cookies);
    }
    return h;
  }));

  const requestHeaders = await Promise.all(entry.request.headers.map(async h => {
    if (h.name.toLowerCase() === 'cookie') {
      return await sanitizeRequestCookieHeader(h, salt, options.cookies);
    }
    if (h.name.toLowerCase() === 'authorization') {
      return await sanitizeAuthorizationHeader(h, salt, options.tokens);
    }
    return h;
  }));

  const requestCookies = entry.request.cookies && await Promise.all(entry.request.cookies.map(async c => {
    const value = options.cookies === 'obfuscate' ?
      'obfuscated' :
      await getSHA256Hash(salt, c.value);
    return { ...c, value };
  }));

  const responseCookies = entry.response.cookies && await Promise.all(entry.response.cookies.map(async c => {
    const value = options.cookies === 'obfuscate' ?
      'obfuscated' :
      await getSHA256Hash(salt, c.value);
    return { ...c, value };
  }));

  return {
    ...entry,
    response: { ...entry.response, headers: responseHeaders, cookies: responseCookies },
    request: { ...entry.request, headers: requestHeaders, cookies: requestCookies },
  };
};

export const sanitize = async (
  har: Har,
  options: Partial<SanitizeOptions> = defaultOptions,
): Promise<Har> => {
  const opts = { ...defaultOptions, ...options };
  const salt = options.salt ? getSalt() : '';
  const entries = await Promise.all(har.log.entries.map(async e => await sanitizeEntry(e, salt, opts)));

  return {
    ...har,
    log: {
      ...har.log,
      creator: { name: pkgName, version: pkgVersion },
      entries
    }
  };
};


