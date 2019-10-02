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
import java.nio.charset.Charset;

public class Encrypt {

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

  public static String generateToken(String salt, String salt2) {
      try
      {
          long time = System.currentTimeMillis();

          long time_60s = time/60000;
          time_60s *= 60000;

          String hash = md5(time_60s+"-5T9[SLt{H.@EtBm$");
          String password = hash.substring(1, 17);
          String password_b64 = Base64.getEncoder().encodeToString(password.getBytes());

          System.err.println(password+" -> "+password_b64+" ("+time+")");

          String ivBase64 = "Acyn/wikMkW4c7+mHtwtfq==";

          String cipherText = encrypt("RTV@"+salt+"-"+time+"-"+salt2, password_b64, ivBase64);
          return cipherText;
      } catch (Exception e) {
          System.out.println(e.toString());
      }
      return null;
  }

  public static String md5(String s)
    {
        MessageDigest digest;
        try
        {
            digest = MessageDigest.getInstance("MD5");
            digest.update(s.getBytes(Charset.forName("US-ASCII")),0,s.length());
            byte[] magnitude = digest.digest();
            BigInteger bi = new BigInteger(1, magnitude);
            String hash = String.format("%0" + (magnitude.length << 1) + "x", bi);
            return hash;
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return null;
    }

  public static void main(String[] args) {

    try
    {   
        // long time = System.currentTimeMillis();
        // String salt = "salt&pepper";
        // String password = (args.length > 0 ? args[0] : "#ABCDEF#ms&%6hcp");
        // String toencrypt = "RTV@"+salt+"_"+time+"_"+salt;

        // String password_b64 = Base64.getEncoder().encodeToString(password.getBytes());


        // String cipherText = encrypt(toencrypt, password_b64, ivBase64);
        // // String decryptedCipherText = decrypt(cipherText, encryptionKeyBase64, ivBase64);

        // System.out.println("Plaintext: " + toencrypt);
        // System.out.println("Password: " + password+" | base64: "+password_b64);
        // System.out.println("Ciphertext: " + cipherText);
        // // System.out.println("Decrypted text: " + decryptedCipherText);
      String mEmail = "Andrew.donald";
      String APIKEY = "fc2760ce-22f0-4f1a-a18b-7b889d47781e";
      String token = generateToken(md5("salt_"+mEmail), md5(mEmail+"_pepper_"+APIKEY));

      System.out.println(token);

    }
    catch (Exception e)
    {
        System.out.println(e.toString());
    }
  }
}
