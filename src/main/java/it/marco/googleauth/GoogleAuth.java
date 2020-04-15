package it.marco.googleauth;

import de.taimos.totp.TOTP;
import it.marco.googleauth.utils.BarCode;
import it.marco.googleauth.utils.SecureKey;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

public class GoogleAuth {

    /**
     * SecureKey object to save the key generated.
     */
    @Getter @Setter
    private SecureKey secureKey;

    /**
     * BarCode object
     */
    @Getter @Setter
    private BarCode barCode;


    /**
     * Generate a secretKey codificated by String base32
     * @return secretKey generated.
     */
    public String createSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    /**
     * get secretkey's code.
     * @param secretKey
     * @return actually code generated for secretKey (param)
     */
    public String getCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    /**
     *
     * @param actCode
     * @return if the actCode (param) it's the same of the code of secretKey'code
     */
    public boolean compareCode(String key, String actCode) {
        String code = getCode(key);
        return code.equals(actCode);
    }

    /**
     * Receive bar code data from google, requires special format, this is the method to generate this data.
     * @param user id in system, username or email
     * @return barcode
     */
    public String getGoogleAuthBarCode(String user){
        try {
            barCode = new BarCode(secureKey, user);
            return "otpath://totp/"
                    + URLEncoder.encode( user, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secureKey.getKey(), "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * display code generated in console every 30 seconds, should be synchronized with code displayed in Google Authenticator app.
     * @param secretKey
     */
    public void syncCodeStamp(String secretKey){
        String lastCode = null;
        while (true) {
            String code = getCode(secretKey);
            if (!code.equals(lastCode))System.out.println(code);

            lastCode = code;
        }
    }

}
