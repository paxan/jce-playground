package com.github.paxan.jceplayground.cmd;

import com.github.paxan.jceplayground.AEAD;

import java.security.GeneralSecurityException;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

class AEADDecrypt {
    public static void main(String[] args) throws GeneralSecurityException {
        byte[] aesKey = args[0].getBytes(UTF_8);
        byte[] nonce = Base64.getDecoder().decode(args[1]);
        byte[] ciphertext = Base64.getDecoder().decode(args[2]);
        AEAD AEAD = new AEAD();
        byte[] plaintext = AEAD.decrypt(aesKey, nonce, ciphertext,
                args.length > 3 ? args[3].getBytes(UTF_8) : null);
        System.out.printf("plaintext:%n%s%n", new String(plaintext, UTF_8));
    }
}
