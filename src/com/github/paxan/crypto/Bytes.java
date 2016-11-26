package com.github.paxan.crypto;

import java.nio.charset.Charset;
import java.util.Base64;

public class Bytes {
    final byte[] b;

    private Bytes(byte[] b) {
        this.b = b;
    }

    public static Bytes wrap(byte[] b) {
        return new Bytes(b);
    }

    public static Bytes decode(String s) {
        return new Bytes(Base64.getDecoder().decode(s));
    }

    public String base64() {
        return Base64.getEncoder().encodeToString(b);
    }

    public String string(Charset charset) {
        return new String(b, charset);
    }
}
