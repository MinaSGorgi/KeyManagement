package core;

import java.math.BigInteger;


/**
 * POJO for storing ElGamal Signature.
 * @author Mina Sami
 * @version 1.0
 */
public class Signature {
    private final BigInteger s1, s2;

    public Signature(BigInteger s1, BigInteger s2) {
        this.s1 = s1;
        this.s2 = s2;
    }

    public BigInteger getS1() {return s1;}
    public BigInteger getS2() {return s2;}

    public void print() {
        System.out.println("s1 = " + s1 + " s2 = " + s2);
    }
}