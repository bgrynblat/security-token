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

const t = parseInt(Date.now()/60000)*60000
var password = t+"-5T9[SLt{H.@EtBm$"
password = crypto.createHash('md5').update(password).digest('hex').substring(1,17)

const pass_b64 = Buffer.from(password, 'utf8').toString('base64');

console.log(password, "->", pass_b64, `(${t})`)

// var keyBase64 = "DWIzFkO22qfVMgx2fIsxOXnwz10pRuZfFJBvf4RS3eY=";
var keyBase64 = pass_b64;
// var ivBase64 = 'AcynMwikMkW4c7+mHtwtfw==';
var ivBase64 = 'Acyn/wikMkW4c7+mHtwtfq==';
var plainText = 'Hello world!';

var cipherText = process.argv[2] || encrypt(plainText, keyBase64, ivBase64);
var decryptedCipherText = decrypt(cipherText, keyBase64, ivBase64);

console.log('Algorithm: ' + getAlgorithm(keyBase64));
!process.argv[2] && console.log('Plaintext: ' + plainText);
console.log('Ciphertext: ' + cipherText);
console.log('Decoded Ciphertext: ' + decryptedCipherText);

const part = decryptedCipherText.split("@")[1]
const split = part.split("-")
const h1 = split[0]
const time = split[1]
const h2 = split[2]

const user_email = "Andrew.donald"
const APIKEY = "fc2760ce-22f0-4f1a-a18b-7b889d47781e"
const hashes = {
    h1: `salt_${user_email}`,
    h2: `${user_email}_pepper_${APIKEY}`
}
var r1 = crypto.createHash('md5').update(hashes.h1).digest('hex');
var r2 = crypto.createHash('md5').update(hashes.h2).digest('hex');
// console.log(hash)

const str = `RTV@${r1}-${time}-${r2}`

console.log("time:", new Date(parseInt(time)))
console.log("DEC:",decryptedCipherText)
console.log("RES:",str)

if(str === decryptedCipherText)     console.log("SUCCESS")
else                                console.log("INVALID")