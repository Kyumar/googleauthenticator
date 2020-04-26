package it.marco.example;

import it.marco.googleauth.GoogleAuth;

import java.util.Scanner;

public class GAuth {

    public static void main(String[] args){
        //GoogleAuth class declaration and instantiation
        GoogleAuth googleAuth = new GoogleAuth();
        String key, code;
        int choose;

        //Generate the random key by the method createSecretKey();
        key = googleAuth.createSecretKey();
        System.out.println("Your key: " + key + " save them!");

        do {
            System.out.println("Choose: " +
                    "\n1. Codes sync stamp of a key. (the method contains an infinite loop, try it last)." +
                    "\n2. Insert a code and check if the same of the generated code of a key." + "" +
                    "\n0. exit.");
            choose = insertInt();

            switch (choose){
                case 1:
                    /*
                        stamp in sync the codes of a key (every timestamp (30seconds) )
                     */
                    googleAuth.syncCodeStamp(key);
                    break;
                case 2:
                     /*
                        with do-while cycle we can make sure that the user has to enter the code so that it is not exact
                        using compareCode method, it go out from the method if the codes are the same.
                    */
                    do {
                        System.out.println("Insert the code!");
                        code = insertString();
                    } while (!googleAuth.compareCode(key, code));
                    System.out.println("Thank you!");
                    break;
                case 0:
                    System.out.println("bye");
                    break;
            }
        } while (choose != 0);
    }

    /*
     very simple method to input String
    */
    private static String insertString(){
        Scanner scanner = new Scanner(System.in);

        return scanner.next();
    }


    /*
     very simple method to input int
    */
    private static int insertInt(){
        Scanner scanner = new Scanner(System.in);

        return scanner.nextInt();
    }
}
