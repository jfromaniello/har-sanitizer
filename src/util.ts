import { getRandomValues, subtle } from 'uncrypto';

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
