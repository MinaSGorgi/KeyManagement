package core;

import java.math.BigInteger;


/**
 * POJO for storing ElGamal Signature.
 * @author Mina Sami
 * @version 1.0
 */
public class Signature {
    private final BigInteger r, s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public BigInteger getR() {return r;}
    public BigInteger getS() {return s;}

    public void print() {
        System.out.println("r = " + r + " s = " + s);
    }
}