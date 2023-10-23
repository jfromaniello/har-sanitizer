## Sanitize HAR files

The HTTP Archive format or HAR is an archive file format in JSON format, for recording the interaction of a web browser with a site. The common extension for these files is .har.

They are commonly used for troubleshooting issues in web applications.

Since they content all the information from the http protocol, they also include generally very sensitive information such as cookies and authorization headers.

This is a library to obfuscate but not to remove the sensitive information. It uses SHA-256 with a randomly generated salt string for each function call.

It can be used in the browser.

## Usage as library

```js
const {sanitize} = require('har-sanitizer');
// import {sanitize} from 'har-sanitizer';

const sanitized = await sanitize(parsedHAR);
```

## Usage as cli

```
npx har-sanitizer request.har
```

## License

MIT 2023 - Jose F. Romaniello
