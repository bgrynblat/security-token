import javax.crypto.spec.*;
import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.math.BigInteger;
import java.nio.ByteOrder;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;

public class Encrypt {

// private static final char[] LOOKUP_TABLE_LOWER = new char[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
// private static final char[] LOOKUP_TABLE_UPPER = new char[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

// public static String encodeHex(byte[] byteArray, boolean upperCase, ByteOrder byteOrder) {

//     // our output size will be exactly 2x byte-array length
//     final char[] buffer = new char[byteArray.length * 2];

//     // choose lower or uppercase lookup table
//     final char[] lookup = upperCase ? LOOKUP_TABLE_UPPER : LOOKUP_TABLE_LOWER;

//     int index;
//     for (int i = 0; i < byteArray.length; i++) {
//         // for little endian we count from last to first
//         index = (byteOrder == ByteOrder.BIG_ENDIAN) ? i : byteArray.length - i - 1;

//         // extract the upper 4 bit and look up char (0-A)
//         buffer[i << 1] = lookup[(byteArray[index] >> 4) & 0xF];
//         // extract the lower 4 bit and look up char (0-A)
//         buffer[(i << 1) + 1] = lookup[(byteArray[index] & 0xF)];
//     }
//     return new String(buffer);
// }

// public static String encodeHex(byte[] byteArray) {
//     return encodeHex(byteArray, true, ByteOrder.BIG_ENDIAN);
// }

// public static SecretKey generateKey(String password) 
//     throws NoSuchAlgorithmException, InvalidKeySpecException 
// { 
//     return new SecretKeySpec(password.getBytes(), "AES"); 
// }

// public static byte[] encryptMsg(String message, SecretKey secret)
//     throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException 
// { 
//    /* Encrypt the message. */
//    Cipher cipher = null; 
//    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//    cipher.init(Cipher.ENCRYPT_MODE, secret); 

//    System.out.println("IV: "+new String(cipher.getIV()));

//    byte[] cipherText = cipher.doFinal(message.getBytes("UTF-8")); 
//    return cipherText; 
// }

// public static String decryptMsg(byte[] cipherText, SecretKey secret) 
//     throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException 
// {
//     /* Decrypt the message, given derived encContentValues and initialization vector. */
//     Cipher cipher = null;
//     cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//     cipher.init(Cipher.DECRYPT_MODE, secret); 
//     String decryptString = new String(cipher.doFinal(cipherText), "UTF-8");
//     return decryptString; 
// }

    public static String encrypt(String plainText, String keyBase64, String ivBase64) throws Exception
    {
        byte[] plainTextArray = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] keyArray = DatatypeConverter.parseBase64Binary(keyBase64);
        byte[] iv = DatatypeConverter.parseBase64Binary(ivBase64);

        SecretKeySpec secretKey = new SecretKeySpec(keyArray, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");   
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(DatatypeConverter.printBase64Binary(cipher.doFinal(plainTextArray)));
    }

    public static String decrypt(String messageBase64, String keyBase64, String ivBase64) throws Exception {

        byte[] messageArray = DatatypeConverter.parseBase64Binary(messageBase64);
        byte[] keyArray = DatatypeConverter.parseBase64Binary(keyBase64);
        byte[] iv = DatatypeConverter.parseBase64Binary(ivBase64);

        SecretKey secretKey = new SecretKeySpec(keyArray, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(messageArray));
    }

    public static void main(String[] args) {

      try
      {   
          long time = System.currentTimeMillis();
          String salt = "salt&pepper";
          String password = (args.length > 0 ? args[0] : "#ABCDEF#ms&%6hcp");
          String toencrypt = "RTV@"+salt+"_"+time+"_"+salt;

          String password_b64 = Base64.getEncoder().encodeToString(password.getBytes());

          // String ivBase64 = "AcynMwikMkW4c7+mHtwtfw==";
          String ivBase64 = "Acyn/wikMkW4c7+mHtwtfq==";

          String cipherText = encrypt(toencrypt, password_b64, ivBase64);
          // String decryptedCipherText = decrypt(cipherText, encryptionKeyBase64, ivBase64);

          System.out.println("Plaintext: " + toencrypt);
          System.out.println("Password: " + password+" | base64: "+password_b64);
          System.out.println("Ciphertext: " + cipherText);
          // System.out.println("Decrypted text: " + decryptedCipherText);
      }
      catch (Exception e)
      {
          System.out.println(e.toString());
      }
    }
  }

  // public static void main(String args[]) {

  //   try {
  //     

  //     System.out.println("TO ENCRYPT: "+toencrypt);
  //     // System.out.println("PASSWORD: "+password);
  //     // SecretKey key = generateKey(password);
  //     // String b64key = Base64.getEncoder().encodeToString(key.getEncoded());
  //     // System.out.println("SECRET KEY: "+b64key);

  //     // byte[] enc = encryptMsg(toencrypt, key);
  //     // System.out.println("ENCRYPTED: "+new String(enc));
      
  //     // String hex = encodeHex(enc);
  //     // System.out.println("ENCRYPTED HEX: "+hex);

  //     // String enc_string = Base64.getEncoder().encodeToString(enc);
  //     // System.out.println("ENCRYPTED base64: "+enc_string);

  //   } catch(Exception e) {
  //     System.out.println("ERROR:"+e);
  //   }

  // }

// }
