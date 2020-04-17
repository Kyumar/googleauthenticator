package it.marco.googleauth.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
public class SecureKey {
    /**
     * secretKey
     */
    @Getter @Setter
    private String key;

    /**
     * method overwritten from Object class, return the key.
     * @return secretKey
     */
    @Override
    public String toString(){
        return key;
    }

    /**
     * method overwritten from Object class, see if the keys are the same.
     * @param object
     * @return if keys are the same
     */
    @Override
    public boolean equals(Object object) {
        boolean state = false;

        if(object instanceof SecureKey && object != null){
            SecureKey secureKey = (SecureKey) object;
            if(secureKey.key.equalsIgnoreCase(key)) state = true;
        }

        return state;
    }
}
