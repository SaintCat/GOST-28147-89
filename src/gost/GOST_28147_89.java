/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gost;

import java.util.Arrays;

/**
 *
 * @author Chernyshov
 */
public class GOST_28147_89 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        byte[] message = "message1message2".getBytes();
        byte[] key = "zdesdoasdfotibbzxce32simvolvoaaa".getBytes();

        StringBuilder encrypt = new StringBuilder();
        StringBuilder crypt = new StringBuilder();
        Gost28147Impl manager = new Gost28147Impl(key);

        for (int i = 0; i < message.length; i += 8) {
            if (message.length - i < 8) {
                break;
            }
            byte[] word = new byte[8];
            System.arraycopy(message, i, word, 0, word.length);
            byte[] encryp = new byte[word.length];
            byte[] decrypted = new byte[word.length];
            manager.ECB(word, encryp, true);
            encrypt.append(new String(encryp));
            manager.ECB(encryp, decrypted, false);
            crypt.append(new String(decrypted));
        }
        System.out.println("Open text: " + new String(message));
        System.out.println("Key: " + new String(key));
        System.out.println("Encrypted: " + encrypt.toString());
        System.out.println("Decrypted: " + crypt.toString());
    }
}
