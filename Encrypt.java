import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Encrypt {

public static SecretKey generateKey(String password) 
    throws NoSuchAlgorithmException, InvalidKeySpecException 
{ 
    return new SecretKeySpec(password.getBytes(), "AES"); 
}

public static byte[] encryptMsg(String message, SecretKey secret)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException 
{ 
   /* Encrypt the message. */
   Cipher cipher = null; 
   cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
   cipher.init(Cipher.ENCRYPT_MODE, secret); 
   byte[] cipherText = cipher.doFinal(message.getBytes("UTF-8")); 
   return cipherText; 
}

public static String decryptMsg(byte[] cipherText, SecretKey secret) 
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException 
{
    /* Decrypt the message, given derived encContentValues and initialization vector. */
    Cipher cipher = null;
    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secret); 
    String decryptString = new String(cipher.doFinal(cipherText), "UTF-8");
    return decryptString; 
}

public static void main(String args[]) {

  try {
  	long time = System.currentTimeMillis();
    String salt = "salt&pepper";
    String password = (args.length > 0 ? args[0] : "#ABCDEF#");

    String toencrypt = "RTV@"+salt+"_"+time+"_"+salt;
    System.out.println("TO ENCRYPT: "+toencrypt);
    // System.out.println("PASSWORD: "+password);
    SecretKey key = generateKey(password);
    System.out.println("SECRET KEY: "+key.getEncoded());

    byte[] enc = encryptMsg(toencrypt, key);
    System.out.println("ENCRYPTED: "+new String(enc));
    String enc_string = Base64.getEncoder().encodeToString(enc);

    System.out.println("ENCRYPTED base64: "+enc_string);

  } catch(Exception e) {
    System.out.println("ERROR:"+e);
  }

}

}
