package com.github.paxan.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * AES-based Authenticated Encryption implementation.
 */
public class AE {
    public static class EncryptionOutcome {
        private final Bytes nonce;
        private final Bytes ciphertext;

        EncryptionOutcome(byte[] nonce, byte[] ciphertext) {
            this.nonce = Bytes.wrap(nonce);
            this.ciphertext = Bytes.wrap(ciphertext);
        }

        public Bytes nonce() {
            return nonce;
        }

        public Bytes ciphertext() {
            return ciphertext;
        }
    }

    private static final SecureRandom RNG = new SecureRandom();
    private static final String AEAD_CIPHER = "AES/GCM/NoPadding";

    public EncryptionOutcome encrypt(Bytes aesKey, Bytes plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(AEAD_CIPHER);
            byte[] nonce = new byte[12];
            RNG.nextBytes(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, specForKey(aesKey.b), standardGCMParam(nonce));
            return new EncryptionOutcome(nonce, cipher.doFinal(plaintext.b));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
                | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("encryption error", e);
        }
    }

    public Bytes decrypt(Bytes aesKey, Bytes nonce, Bytes ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(AEAD_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, specForKey(aesKey.b), standardGCMParam(nonce.b));
            return Bytes.wrap(cipher.doFinal(ciphertext.b));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
                | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("decryption error", e);
        }
    }

    private static SecretKeySpec specForKey(byte[] aesKey) {
        return new SecretKeySpec(aesKey, "AES");
    }

    private static GCMParameterSpec standardGCMParam(byte[] nonce) {
        return new GCMParameterSpec(16 * 8, nonce);
    }
}
