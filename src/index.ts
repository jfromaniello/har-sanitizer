import simpleCookie from "simple-cookie";
import { Har, HarContent, HarEntry, HarHeader, HarPostData } from "./har";
import { formatBody, getSHA256Hash, getSalt, isBodySanitizable, parseBody } from "./util";
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

/**
 * this fields are always obfuscated from body
 */
const sensitiveFields = [
  "password",
  "passwd",
  "pass",
  "userPassword",
  "pwd",
  'username',
  'user',
  'user_id',
  'user_email',
  'email',
  'mail',
  'login',
  'login_id',
  'login_email',
  'login_email_address',
  'ip',
  'ip_address',
  'ipaddress',
  'client_secret',
  'secret'
];

const tokenFieldNames = [
  'access_token',
  'id_token',
  'code',
  'refresh_token',
  'token',
];

async function sanitizeBody<T extends HarPostData | HarContent>(content: T, salt: string, tokensType: SanitizationType): Promise<T> {
  if (!isBodySanitizable(content)) {
    return {
      ...content,
      text: 'obfuscated',
    };
  }

  const parsed = parseBody(content);
  sensitiveFields.forEach((fieldName) => {
    if (fieldName in parsed) {
      parsed[fieldName] = 'obfuscated';
    }
  });
  await Promise.all(tokenFieldNames.map((async (fieldName) => {
    if (fieldName in parsed) {
      parsed[fieldName] = tokensType === 'obfuscate' ?
        'obfuscated' :
        await getSHA256Hash(salt, parsed[fieldName]);
    }
  })));
  return formatBody(content, parsed);
}

async function sanitizeURL(url: string, salt: string, tokensType: SanitizationType): Promise<string> {
  const parsed = new URL(url);
  const { searchParams } = parsed;

  sensitiveFields.forEach((fieldName) => {
    if (searchParams.has(fieldName)) {
      searchParams.set(fieldName, 'obfuscated');
    }
  });

  await Promise.all(tokenFieldNames.map(async (fieldName) => {
    if (searchParams.has(fieldName)) {
      searchParams.set(fieldName, tokensType === 'obfuscate' ?
        'obfuscated' :
        await getSHA256Hash(salt, searchParams.get(fieldName)!));
    }
  }));

  return parsed.href;
};

/**
 * Sanitizes a given HAR entry by obfuscating or hashing sensitive data.
 * @param entry - The HAR entry to sanitize.
 * @param salt - A salt value used for hashing sensitive data.
 * @param options - An object containing options for sanitization.
 * @returns A Promise that resolves to the sanitized HAR entry.
 */
const sanitizeEntry = async (entry: HarEntry, salt: string, options: SanitizeOptions): Promise<HarEntry> => {
  const responseHeaders = await Promise.all(entry.response.headers.map(async h => {
    if (h.name.toLowerCase() === 'set-cookie') {
      return await sanitizeResponseSetCookie(h, salt, options.cookies);
    }
    if (h.name.toLowerCase() === 'location') {
      return {
        name: h.name,
        value: await sanitizeURL(h.value, salt, options.tokens),
      };
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
    if (h.name.toLowerCase() === 'referer') {
      return {
        name: h.name,
        value: await sanitizeURL(h.value, salt, options.tokens),
      };
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

  const requestPostData = entry.request.postData &&
    await sanitizeBody(entry.request.postData, salt, options.tokens);

  const requestURL = entry.request.url &&
    await sanitizeURL(entry.request.url, salt, options.tokens);

  const responseContent = entry.response.content &&
    await sanitizeBody(entry.response.content, salt, options.tokens);

  return {
    ...entry,
    request: {
      ...entry.request,
      url: requestURL,
      headers: requestHeaders,
      cookies: requestCookies,
      postData: requestPostData
    },
    response: { ...entry.response, headers: responseHeaders, cookies: responseCookies, content: responseContent },
  };
};

/**
 * Sanitizes a given HTTP Archive (HAR) object by removing sensitive information from its entries.
 * @param har The HAR object to sanitize.
 * @param options An optional object containing the sanitization options.
 * @returns A Promise that resolves to the sanitized HAR object.
 */
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


