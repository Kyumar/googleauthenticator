package it.marco.googleauth.codes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;

public class TOTP {

    /**
     * HmadSHA1 algorithm
     */
    private static final String HMAC_SHA1 = "HmacSHA1";

    /**
     * overloaded method, so that when the method is invoked
     * the time does not have to be specified each time
     * @param key secureKey
     * @return a String
     */
    public String getOTP(String key){
        return getOTP(getStep(), key);
    }

    /**
     * this method get the code from a key
     * calculated by an algorithm
     * @param step the seconds to reload code
     * @param key the secureKey
     * @return a String
     */
    private String getOTP(long step, String key) {
        StringBuilder steps = new StringBuilder(Long.toHexString(step).toUpperCase());
        while (steps.length() < 16) {
            steps.insert(0, "0");
        }

        byte[] msg = hexStr2Bytes(steps.toString());
        byte[] k = hexStr2Bytes(key);

        byte[] hmacComputedHash = hmac_sha1(k, msg);

        int offset = hmacComputedHash[hmacComputedHash.length - 1] & 0xf;
        int binary = ((hmacComputedHash[offset] & 0x7f) << 24)
                | ((hmacComputedHash[offset + 1] & 0xff) << 16)
                | ((hmacComputedHash[offset + 2] & 0xff) << 8)
                | (hmacComputedHash[offset + 3] & 0xff);

        int otp = binary % 1000000;

        StringBuilder result = new StringBuilder(Integer.toString(otp));
        while (result.length() < 6) {
            result.insert(0, "0");
        }

        return result.toString();
    }

    /**
     * This method encode a String in an array of byte only if the string
     * contains even number of characters
     * @param string the string to encode
     * @return array of byte
     */
    private byte[] hexStr2Bytes(String string) {
        if ((string.length() % 2) != 0)
            throw new IllegalArgumentException("String must be contain even number of characters");

        int len = string.length();
        byte[] result = new byte[string.length() / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
            + Character.digit(string.charAt(i+1), 16));
        }
        return result;
    }

    /**
     * This method uses the JCE to provide the crypto algorithm (Hmac_SHA1).
     * HMAC computes a Hashed Message Authentication Code
     *
     * @param keyBytes   the bytes to use for the HMAC key
     * @param text       the message or text to be authenticated (the code).
     */
    private byte[] hmac_sha1(byte[] keyBytes, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(HMAC_SHA1);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * This method get currentTimeMillis divided by 30000, it returns 30 (seconds)
     * @return 30s
     */
    private long getStep(){
        return System.currentTimeMillis() / (30 * 1000);
    }
}
