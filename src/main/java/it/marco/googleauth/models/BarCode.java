package it.marco.googleauth.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
public class BarCode {

    /**
     * SecureKey
     */
    @Getter @Setter
    private SecureKey secureKey;

    /**
     * companyName and user
     */
    @Getter @Setter
    private String companyName, user;

    /**
     * overloading constructor
     * @param secureKey
     * @param user
     */
    public BarCode(SecureKey secureKey, String user){
        this.secureKey = secureKey;
        this.user = user;
    }

    /**
     * return informations of a BarCode (key, companyName, user)
     * @return a String
     */
    @Override
    public String toString(){
        return "info: " +
                "\nkey: " + secureKey +
                "\ncompany: " + companyName +
                "\nuser: " + user;
    }

    /**
     * check if an Object BarCode have same features of another (param)
     * @param object
     * @return boolean
     */
    @Override
    public boolean equals(Object object){
        boolean state = false;

        if(object != null && object instanceof BarCode){
            BarCode barCode = (BarCode) object;
            if(barCode.companyName.equals(companyName) && barCode.user.equals(user) && barCode.secureKey.equals(secureKey)) state = true;
        }

        return state;
    }
}
