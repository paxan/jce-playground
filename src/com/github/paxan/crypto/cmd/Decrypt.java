package com.github.paxan.crypto.cmd;

import com.github.paxan.crypto.AE;
import com.github.paxan.crypto.Bytes;

import java.nio.charset.StandardCharsets;

class Decrypt {
    public static void main(String[] args) {
        Bytes aesKey = Bytes.wrap(args[0].getBytes(StandardCharsets.UTF_8));
        Bytes nonce = Bytes.decode(args[1]);
        Bytes ciphertext = Bytes.decode(args[2]);
        AE ae = new AE();
        System.out.printf("plaintext:%n%s%n", ae.decrypt(aesKey, nonce, ciphertext).string(StandardCharsets.UTF_8));
    }
}
