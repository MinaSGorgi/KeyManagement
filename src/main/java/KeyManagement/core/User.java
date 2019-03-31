package core;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * Represents a user of the ElGamal algorithm for Digital Signature.
 * Implemented from "Cryptography and Network Security" Fifth Edition by William Stallings.
 * @author Mina Sami
 * @version 1.0
 */
class User {
    private final static SecureRandom secureRandom = new SecureRandom();
    private final static BigInteger BI_ONE = BigInteger.ONE;
    private final static BigInteger BI_TWO = new BigInteger("2");

    private final BigInteger privateKey, publicKey;
    private final ElGamal gamal;

    /**
     * Applies following constrain(s) when generating user keys:
     *      . 1 < privateKey < p − 2.
     */
    public User(ElGamal gamal) {
        BigInteger p = gamal.getP(), g = gamal.getG();

        BigInteger tempPrivateKey;
        do {
            tempPrivateKey = new BigInteger(p.bitLength(), secureRandom);
        } while(BI_ONE.compareTo(tempPrivateKey) >= 0
                || tempPrivateKey.compareTo(p.subtract(BI_TWO)) >= 0);

        privateKey = tempPrivateKey;
        publicKey = g.modPow(privateKey, p);
        this.gamal = gamal;
    }

    public BigInteger getPublicKey() {return publicKey;}

    public void print() {
        System.out.println("privateKey = " + privateKey + " publicKey = " + publicKey);
    }

    /**
     * Applies following constrain(s) when signing message:
     *      . 0 <= message <= p - 1 // TODO: IMPLEMENT ME
     *      . 1 < k < p − 1 and gcd(k, p − 1) = 1
     *      . s != 0
     * 
     * @param message message to be digitally signed
     * @return
     */
    public Signature sign(BigInteger message) {
        BigInteger p = gamal.getP(), pm1 = p.subtract(BI_ONE), g = gamal.getG();
        BigInteger hashedMessage = gamal.hash(message);
        BigInteger r, s, kinv;

        do {
            BigInteger k;
            do {
                k = new BigInteger(p.bitLength(), secureRandom);
            } while(BI_ONE.compareTo(k) >= 0 || k.compareTo(pm1) >= 0
                    || k.gcd(pm1).compareTo(BI_ONE) != 0);
    
            kinv = k.modInverse(p.subtract(BI_ONE));
            r = g.modPow(k, p);
            s = (hashedMessage.subtract(privateKey.multiply(r))).multiply(kinv).mod(p.subtract(BI_ONE));
        } while(s.compareTo(BigInteger.ZERO) == 0);

        return new Signature(r, s);
    }

    public boolean verify(Signature signature, BigInteger message, BigInteger otherPublicKey) {
        BigInteger p = gamal.getP(), g = gamal.getG();
        BigInteger r = signature.getR(), s = signature.getS();
        BigInteger hashedMessage = gamal.hash(message);

        BigInteger v1 = g.modPow(hashedMessage, p);
        BigInteger v2 = otherPublicKey.modPow(r, p).multiply(r.modPow(s, p)).mod(p);

        return v1.compareTo(v2) == 0;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int nBits = Integer.parseInt(args[0]);
        String hash = args[1];

        ElGamal gamal = new ElGamal(nBits, hash);
        gamal.print();

        BigInteger message;
        do {
            message = new BigInteger(nBits, new SecureRandom());
        } while(message.compareTo(gamal.getP()) >= 0);
        System.out.println("message " + message);

        User user1 = new User(gamal);
        User user2 = new User(gamal);
        user1.print();

        System.out.println(user2.verify(user1.sign(message), message, user1.publicKey) ? "Verified" : "Not Verified");
    }
}