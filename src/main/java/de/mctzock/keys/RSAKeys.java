/*
 * Copyright (c) 2021 Ben Siebert. All rights reserved.
 */
package de.mctzock.keys;

import de.mctzock.keys.annotation.Experimental;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeys {

    /**
     * Generate Keys
     * @param size Keysize
     * @return KeyPair
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair gen(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        KeyPair key = generator.generateKeyPair();
        return key;
    }

    /**
     * Encrypt a message
     * @param message Message
     * @param pubKey Public Key
     * @return encrypted message as byte array
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] encrypt(String message, PublicKey pubKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] enc = cipher.doFinal(message.getBytes());
        return enc;
    }

    /**
     * Decrypt message
     * @param message encrypted message as byte array
     * @param privKey Private Key
     * @return decrypted Message as String
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static String decrypt(byte[] message, PrivateKey privKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] dec = null;
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec params = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privKey, params);
        dec = cipher.doFinal(message);
        return new String(dec);
    }

    /**
     * Get Public Key from String. You can use this for reading the public key form a file.
     * @param s Public Key as String
     * @return Public Key Object
     */
    public static PublicKey pubFromString(String s) {
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] pubBytes = s.getBytes();
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(pubBytes));
        RSAPublicKey pubKey = null;
        try {
            pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return pubKey;
    }

    /**
     * Get Private Key from String. You can use this for reading the private key form a file.
     * @param s Private Key as String
     * @return Private Key Object
     */
    @Experimental
    public static PrivateKey privFromString(String s){
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] privBytes = s.getBytes();
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privBytes));
        PrivateKey privKey = null;
        try {
            privKey = kf.generatePrivate(keySpecPKCS8);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privKey;
    }
}
