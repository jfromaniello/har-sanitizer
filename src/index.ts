import simpleCookie from "simple-cookie";
import { getRandomValues } from "uncrypto";
import { Har, HarEntry, HarHeader } from "./har";
import { getSHA256Hash, getSalt } from "./util";

async function sanitizeAuthorizationHeader(h: HarHeader, salt: string) {
  const [scheme, value] = h.value.split(/\s(.+)/);
  const hashed = await getSHA256Hash(salt, value);
  return { ...h, value: `${scheme} ${hashed}` };
}

async function sanitizeRequestCookieHeader(h: HarHeader, salt: string) {
  const result = await Promise.all(h.value.split(/;\s?/g).map(async (s) => {
    const [name, value] = s.split(/=(.*)/);
    const hashed = await getSHA256Hash(salt, value);
    return `${name}=${hashed}`;
  }));
  const value = result.join('; ') + ';';
  return { ...h, value };
}

async function sanitizeResponseSetCookie(h: HarHeader, salt: string) {
  const cookie = simpleCookie.parse(h.value);
  cookie.value = await getSHA256Hash(salt, cookie.value);
  const value = simpleCookie.stringify(cookie);
  return { ...h, value };
}

const sanitizeEntry = async (salt: string, entry: HarEntry): Promise<HarEntry> => {
  const responseHeaders = await Promise.all(entry.response.headers.map(async h => {
    if (h.name.toLowerCase() === 'set-cookie') {
      return await sanitizeResponseSetCookie(h, salt);
    }
    return h;
  }));

  const requestHeaders = await Promise.all(entry.request.headers.map(async h => {
    if (h.name.toLowerCase() === 'cookie') {
      return await sanitizeRequestCookieHeader(h, salt);
    }
    if (h.name.toLowerCase() === 'authorization') {
      return await sanitizeAuthorizationHeader(h, salt);
    }
    return h;
  }));

  const requestCookies = entry.request.cookies && await Promise.all(entry.request.cookies.map(async c => {
    const value = await getSHA256Hash(salt, c.value);
    return { ...c, value };
  }));

  const responseCookies = entry.response.cookies && await Promise.all(entry.response.cookies.map(async c => {
    const value = await getSHA256Hash(salt, c.value);
    return { ...c, value };
  }));

  return {
    ...entry,
    response: { ...entry.response, headers: responseHeaders, cookies: responseCookies },
    request: { ...entry.request, headers: requestHeaders, cookies: requestCookies },
  };
}

export const sanitize = async (har: Har, options: { salt: boolean } = { salt: true }): Promise<Har> => {
  const salt = options.salt ? getSalt() : '';
  const entries = await Promise.all(har.log.entries.map(async e => await sanitizeEntry(salt, e)));
  return { ...har, log: { ...har.log, entries } };
};


