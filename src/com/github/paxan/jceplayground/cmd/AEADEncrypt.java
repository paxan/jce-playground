package com.github.paxan.jceplayground.cmd;

import com.github.paxan.jceplayground.AEAD;

import java.security.GeneralSecurityException;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

class AEADEncrypt {
    public static void main(String[] args) throws GeneralSecurityException {
        byte[] aesKey = args[0].getBytes(UTF_8);
        byte[] plaintext = args[1].getBytes(UTF_8);
        AEAD AEAD = new AEAD();
        com.github.paxan.jceplayground.AEAD.Encrypted e = AEAD.encrypt(aesKey, plaintext,
                args.length > 2 ? args[2].getBytes(UTF_8) : null);
        System.out.printf("cipher:%n%s%n", e.aeadCipher);
        System.out.printf("nonce:%n%s%n", base64(e.nonce));
        System.out.printf("ciphertext:%n%s%n", base64(e.ciphertext));
    }

    private static String base64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}
