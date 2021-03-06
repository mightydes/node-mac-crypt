# node-mac-crypt
Simple NodeJS Crypt Package with Mac Sign.

---
## Usage:

```js
const crypto = require('crypto');
const MacCrypt = require('node-mac-crypt');

const crypt = new MacCrypt({
    key: 'my_secret_password',
    iv: crypto.randomBytes(16)
});

// String:
const message = 'My Secret Message!';
console.log(`Original Message: '${message}'`);

const encrypted = crypt.encrypt(message);
console.log(`Encrypted Message: '${encrypted}'`);

const decrypted = crypt.decrypt(encrypted);
console.log(`Decrypted Message: '${decrypted}'`);

// JSON:
const json = {data: 'My Secret Data!'};
console.log(`Original JSON Data:`, json);

const json_encrypted = crypt.encrypt(json);
console.log(`Encrypted JSON Data: '${json_encrypted}'`);

const json_decrypted = crypt.decrypt(json_encrypted);
console.log(`Decrypted JSON Data:`, json_decrypted);
```

---
## Options

*   `key` _{base64 string|Buffer}_ -- secret key.
*   `iv` _{base64 string|Buffer}_ -- cipher iv (16 bytes length).
*   `cipher` _{string}_ -- cipher algorithm (default `'aes-256-cbc'`).
*   `mac_size` _{integer}_ -- mac sign size (default `6`).
*   `mac_separator` _{string}_ -- mac sign separator (default `'::'`).
*   `key_length` _{integer}_ -- secret key length in bytes (default `32`).
*   `serialize` _{function}_ -- message serialize method (default `JSON.stringify`).
*   `unserialize` _{function}_ -- message unserialize method (default `JSON.parse`).
