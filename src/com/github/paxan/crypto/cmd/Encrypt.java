package com.github.paxan.crypto.cmd;

import com.github.paxan.crypto.AE;
import com.github.paxan.crypto.Bytes;

import java.nio.charset.StandardCharsets;

class Encrypt {
    public static void main(String[] args) {
        Bytes aesKey = Bytes.wrap(args[0].getBytes(StandardCharsets.UTF_8));
        Bytes plaintext = Bytes.wrap(args[1].getBytes(StandardCharsets.UTF_8));
        AE ae = new AE();
        AE.EncryptionOutcome o = ae.encrypt(aesKey, plaintext);
        System.out.printf("nonce:%n%s%n", o.nonce().base64());
        System.out.printf("ciphertext:%n%s%n", o.ciphertext().base64());
    }
}
