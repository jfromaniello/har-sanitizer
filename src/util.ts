import { getRandomValues, subtle } from 'uncrypto';
import mediaTyper from 'media-typer';

import { HarContent, HarPostData } from './har';

function dec2hex(dec: number) {
  return dec.toString(16).padStart(2, "0")
}

export const getSalt = function (len: number = 40) {
  const arr = new Uint8Array((len) / 2)
  getRandomValues(arr)
  return Array.from(arr, dec2hex).join('')
};

export const getSHA256Hash = async (salt: string, input: string) => {
  const textAsBuffer = new TextEncoder().encode(input + salt);
  const hashBuffer = await subtle.digest("SHA-256", textAsBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
  return hash;
};

const getTypeFromPostData = (body: HarPostData | HarContent): string | undefined => {
  const mimeType = /^([^;\s]+)/.exec(body.mimeType)![0];
  if (!mimeType) { return; }
  try {
    const { subtype } = mediaTyper.parse(mimeType);
    return subtype;
  } catch (err) {
    throw new Error(`Invalid mime type: ${mimeType}`);
  }
};

export const parseBody = (body: HarPostData | HarContent): any => {
  if (!body.text) { return; }
  const type = getTypeFromPostData(body);
  switch (type) {
    case 'json':
      return JSON.parse(body.text);
    case 'x-www-form-urlencoded':
      return Object.fromEntries(new URLSearchParams(body.text));
    default:
      throw new Error(`Unsupported mime type: ${type}`);
  }
};

export const formatBody = <T extends HarPostData | HarContent>(body: T, data: any): T => {
  if (!body.text) { return body; }
  const type = getTypeFromPostData(body);
  switch (type) {
    case 'json':
      return { ...body, text: JSON.stringify(data) };
    case 'x-www-form-urlencoded':
      return { ...body, text: new URLSearchParams(data).toString() };
    default:
      throw new Error(`Unsupported mime type: ${type}`);
  }
};

export const isBodySanitizable = (body: HarPostData | HarContent) => {
  if (!body.text) { return false; }
  try {
    const type = getTypeFromPostData(body);
    return type === 'json' || type === 'x-www-form-urlencoded';
  } catch (err) {
    return false;
  }
}
