package core;

import java.math.BigInteger;


/**
 * POJO for storing Signed Encrypted messages.
 * @author Mina Sami
 * @version 1.0
 */
public class Packet {
    private final BigInteger message;
    private final Signature signature;


    public Packet(BigInteger message, Signature signature) {
        this.message = message;
        this.signature = signature;
    }

    public BigInteger getMessage() {return message;}
    public Signature getSignature() {return signature;}

    public void print() {
        System.out.print("packet message = " + message + " ");
        signature.print();
    }
}