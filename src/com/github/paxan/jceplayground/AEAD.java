package com.github.paxan.jceplayground;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Authenticated Encryption with Associated Data (AEAD) with AES.
 */
public class AEAD {
    public static class Encrypted {
        public final String aeadCipher;
        public final byte[] nonce;
        public final byte[] ciphertext;

        Encrypted(byte[] nonce, byte[] ciphertext) {
            this.aeadCipher = AEAD_CIPHER;
            this.nonce = nonce;
            this.ciphertext = ciphertext;
        }
    }

    private static final SecureRandom RNG = new SecureRandom();
    private static final String AEAD_CIPHER = "AES/GCM/NoPadding";

    public Encrypted encrypt(byte[] aesKey, byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance(AEAD_CIPHER);
            byte[] nonce = new byte[12];
            RNG.nextBytes(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, specForKey(aesKey), standardGCMParam(nonce));
            attachAD(associatedData, cipher);
            return new Encrypted(nonce, cipher.doFinal(plaintext));
    }

    public byte[] decrypt(byte[] aesKey, byte[] nonce, byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AEAD_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, specForKey(aesKey), standardGCMParam(nonce));
        attachAD(associatedData, cipher);
        return cipher.doFinal(ciphertext);
    }

    private static SecretKeySpec specForKey(byte[] aesKey) {
        return new SecretKeySpec(aesKey, "AES");
    }

    private static GCMParameterSpec standardGCMParam(byte[] nonce) {
        return new GCMParameterSpec(16 * 8, nonce);
    }

    private static void attachAD(byte[] associatedData, Cipher cipher) {
        if (associatedData != null && associatedData.length != 0) {
            cipher.updateAAD(associatedData);
        }
    }
}
