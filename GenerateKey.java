import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Main { 

    //QA : yF/EQ43WSIfLU/rXpvt3Pi02fxOF59s84OBJy8yzGmU=
    //Stage: XKgmnD0BAaJBwG7DjllHn1vSz4gX1ZyX5pOM/JcBpdk=
    //Prod: 8qL60Kuh9Y+M5L3/Y/SOm/BOLFuDuqR+yDtVPf0kCcs=

    //{"vault_v3":{"value":"<for_key_value_please_connect>","created_at":"2022-10-26T17:29:05.446Z","algorithm":"AES","version":"v3"}}

    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    static String plainText = "This is a plain text which need to be encrypted by Java AES 256 Algorithm in GCM mode";
    public static void main(String args[]) throws Exception{ 
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        SecretKey originalKey = keyGenerator.generateKey();

        byte[] rawData = originalKey.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);

        System.out.println("Generated Key:"+encodedKey);

        String plaintext = "Hi how are you!";
        String iv= "test vector";
        byte[] cipherText = encrypt(plaintext.getBytes(), originalKey, iv.getBytes());
        String decodetext = decrypt(cipherText, originalKey, iv.getBytes());
        System.out.println("Plaint Text:"+plaintext);
        System.out.println("encoded text:"+cipherText);
        System.out.println("decoded Text:"+decodetext);
        
    } 

    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);
        
        return cipherText;
    }

    public static String decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }
}