const crypto = require('crypto');
const MacCrypt = require('../src');

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
