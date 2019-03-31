package core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * Represents ElGamal Digital Signature storing its shared parameters.
 * Implemented from "Cryptography and Network Security" Fifth Edition by William Stallings.
 * @author Mina Sami
 * @version 1.0
 */
class ElGamal {
    private final static SecureRandom secureRandom = new SecureRandom();

    private final MessageDigest messageDigest;
    private final BigInteger p, g;

    /**
     * Applies following constrain(s) when generating ElGamal system parameters:
     *      - p is a prime of nBits length
     *      - g < p and g is a generator of the multiplicative group of integers modulo p
     *      - hash is a collision-resistant hash function
     */
    public ElGamal(int nBits, String hash) throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance(hash);
        p = BigInteger.probablePrime(nBits, secureRandom);
        g = new BigInteger("2"); // TODO: FIX ME
    }

    public BigInteger getP() {return p;}
    public BigInteger getG() {return g;}

    public void print() {
        System.out.println("p = " + p + " g = " + g);
    }

    public BigInteger hash(BigInteger message) {
        return new BigInteger(messageDigest.digest(message.toByteArray()));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int nBits = Integer.parseInt(args[0]);
        String hash = args[1];

        ElGamal gamal = new ElGamal(nBits, hash);
        gamal.print();
    }
}