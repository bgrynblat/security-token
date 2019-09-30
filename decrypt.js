var crypto = require('crypto');

const header = process.argv[2]
console.log("TO DECRYPT base64", header)

const enc = Buffer.from(header, 'base64').toString('utf8');
console.log("TO DECRYPT", enc)

function encrypt(text, password){
  var cipher = crypto.createCipher('aes-128-cbc',password)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}
 
function decrypt(text, password){
  var decipher = crypto.createDecipher('aes-128-cbc',password)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}

const decrypt_key = process.argv[3] || "[B@73035e27"

const dec = decrypt(enc, decrypt_key)
console.log("DECRYPTED", dec)