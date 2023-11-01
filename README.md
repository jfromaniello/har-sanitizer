## Sanitize HAR files

The HTTP Archive format or HAR is an archive file format in JSON format, for recording the interaction of a web browser with a site. The common extension for these files is .har.

They are commonly used for troubleshooting issues in web applications.

Since they content all the information from the http protocol, they also include generally very sensitive information such as cookies and authorization headers.

This is a library to obfuscate sensitive information.

There are currently two modes for cookies and tokens:
- `obfuscate`: the sanitizer will replace the values of the sensitive information with the string `obfuscated`.
- `hash`: the sanitizer will calculate a salt for each time its called and replace the sensitive information with hash SHA256 of the value plus the salt.

Password fields are always obfuscated.

This library can be used in the client-side.

## Usage as library

```js
const {sanitize} = require('har-sanitizer');
// import {sanitize} from 'har-sanitizer';

const sanitized = await sanitize(parsedHAR, {
  cookies: 'hash',
  tokens: 'obfuscate'
});
```

## Usage as cli

```
npx har-sanitizer request.har
```

## License

MIT 2023 - Jose F. Romaniello
