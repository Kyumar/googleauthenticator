package it.marco.googleauth;

import it.marco.googleauth.codes.TOTP;
import it.marco.googleauth.models.BarCode;
import it.marco.googleauth.models.Code;
import it.marco.googleauth.models.SecureKey;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.security.SecureRandom;

public class GoogleAuth {

    /**
     * SecureKey object to save the key generated.
     */
    @Getter @Setter
    private SecureKey secureKey;

    @Getter @Setter
    private Code code;

    /**
     * BarCode object
     */
    @Getter @Setter
    private BarCode barCode;

    /**
     * totp declaration
     */
    private final TOTP totp;

    /**
     * instantiate TOTP
     */
    public GoogleAuth(){
        totp = new TOTP();
    }

    /**
     * Generate a secretKey codificated by String base32
     * and save them to SecureKey object
     * @return secretKey generated.
     */
    public String createSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        Base32 base32 = new Base32();
        secureKey = new SecureKey(base32.encodeToString(bytes));
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
        return totp.getOTP(hexKey);
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
