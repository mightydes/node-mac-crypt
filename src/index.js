const crypto = require('crypto');
const md5 = require('md5');

class MacCrypt {

    constructor(options = {}) {
        ['key', 'iv'].map((prop) => {
            if (!options[prop]) {
                throw new Error(`[node-mac-crypt] Missed mandatory '${prop}' option!`);
            }
        });

        this.options = Object.assign({}, MacCrypt.defaultOptions, options);

        this._key = Buffer.alloc(this.options.key_length, 0);
        if (Buffer.isBuffer(this.options.key)) {
            this._key.write(this.options.key);
        } else {
            this._key.write(this.options.key, 'base64');
        }

        if (Buffer.isBuffer(this.options.iv)) {
            this._iv = Buffer.from(this.options.iv);
        } else {
            this._iv = Buffer.from(this.options.iv, 'base64');
        }
    }

    encrypt(value) {
        const cipher = crypto.createCipheriv(this.options.cipher, this._key, this._iv);
        const serialized = this.options.serialize(value);
        const enc = cipher.update(serialized);
        const finalBuffer = Buffer.concat([enc, cipher.final()]);
        const mac = md5(serialized).substr(0, this.options.mac_size);
        return mac + this.options.mac_separator + finalBuffer.toString('base64');
    }

    decrypt(payload) {
        const mac = payload.substr(0, this.options.mac_size);
        const enc = payload.substr(this.options.mac_size + this.options.mac_separator.length);
        if (mac.length !== this.options.mac_size || !enc) {
            return false;
        }
        try {
            const decipher = crypto.createDecipheriv(this.options.cipher, this._key, this._iv);
            const dec = decipher.update(enc, 'base64');
            const value = Buffer.concat([dec, decipher.final()]).toString();
            if (mac !== md5(value).substr(0, this.options.mac_size)) {
                return false;
            }
            return this.options.unserialize(value);
        } catch (e) {
            return false;
        }
    }

}

MacCrypt.defaultOptions = {
    cipher: 'aes-256-cbc',
    mac_size: 6,
    mac_separator: '::',
    key_length: 32,
    serialize: (value) => JSON.stringify(value),
    unserialize: (value) => JSON.parse(value),
};

module.exports = MacCrypt;
