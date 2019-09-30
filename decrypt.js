var crypto = require('crypto');

function getAlgorithm(keyBase64) {

    var key = Buffer.from(keyBase64, 'base64');
    switch (key.length) {
        case 16:
            return 'aes-128-cbc';
        case 32:
            return 'aes-256-cbc';

    }

    throw new Error('Invalid key length: ' + key.length);
}

function encrypt(text, pass_b64, iv_b64) {

    var key = Buffer.from(pass_b64, 'base64');
    var iv = Buffer.from(iv_b64, 'base64');

    var cipher = crypto.createCipheriv(getAlgorithm(pass_b64),key,iv)
    let cip = cipher.update(text, 'utf8', 'base64')
    cip += cipher.final('base64');
    return cip;
}
 
function decrypt(textb64, pass_b64, iv_b64){

    var key = Buffer.from(pass_b64, 'base64');
    var iv = Buffer.from(iv_b64, 'base64');

    var decipher = crypto.createDecipheriv(getAlgorithm(pass_b64), key, iv);
    let dec = decipher.update(textb64, 'base64');
    dec += decipher.final();
    return dec;
}


const password = "#ABCDEF#ms&%6hcp"
const pass_b64 = Buffer.from(password, 'utf8').toString('base64');

// var keyBase64 = "DWIzFkO22qfVMgx2fIsxOXnwz10pRuZfFJBvf4RS3eY=";
var keyBase64 = pass_b64;
// var ivBase64 = 'AcynMwikMkW4c7+mHtwtfw==';
var ivBase64 = 'Acyn/wikMkW4c7+mHtwtfq==';
var plainText = 'Hello world!';

var cipherText = process.argv[2] || encrypt(plainText, keyBase64, ivBase64);
var decryptedCipherText = decrypt(cipherText, keyBase64, ivBase64);

console.log('Algorithm: ' + getAlgorithm(keyBase64));
console.log('Plaintext: ' + plainText);
console.log('Ciphertext: ' + cipherText);
console.log('Decoded Ciphertext: ' + decryptedCipherText);