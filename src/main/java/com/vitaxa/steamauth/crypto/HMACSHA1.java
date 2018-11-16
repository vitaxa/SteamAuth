package com.vitaxa.steamauth.crypto;

import com.vitaxa.steamauth.helper.IOHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class HMACSHA1 {

    private static final Logger LOG = LoggerFactory.getLogger(HMACSHA1.class);

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static Mac MAC;

    static {
        try {
            MAC = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Exception while initializing crypto algorithm", e);
        }
    }

    private HMACSHA1() {
    }

    public static byte[] calculate(byte[] bytes, byte[] key) throws InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
        MAC.init(signingKey);

        return MAC.doFinal(bytes);
    }

    public static String digest(String data, String key) throws InvalidKeyException {
        return toHexString(calculate(data.getBytes(IOHelper.UNICODE_CHARSET), IOHelper.encode(key)));
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder hash = new StringBuilder();
        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xFF & aByte);
            if (hex.length() == 1) {
                hash.append('0');
            }
            hash.append(hex);
        }
        return hash.toString();
    }
}
