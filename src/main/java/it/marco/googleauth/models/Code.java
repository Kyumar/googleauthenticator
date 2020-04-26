package it.marco.googleauth.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
public class Code {

    /**
     * the code
     */
    @Getter @Setter
    private String code;

    /**
     * the secret key of the code
     */
    @Getter
    private String key;

    /**
     * timeStamp of the code
     */
    @Getter @Setter
    private long timeStamp;

    /**
     * overwritten method of Object class,
     * @return the code
     */
    @Override
    public String toString() {
        return code;
    }

    /**
     * overwritten method of Object class, see if the Code are the same (it checks code and key of the object).
     * @param object
     * @return boolean
     */
    @Override
    public boolean equals(Object object){
        boolean state = false;
        if(object != null && object instanceof Code){
            Code code = (Code) object;
            if(code.code.equals(this.code) && code.key.equals(this.key)) state = true;
        }

        return state;
    }
}
