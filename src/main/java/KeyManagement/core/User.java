package core;

import java.math.BigInteger;
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
     *      . 1 < privateKey < q − 2.
     */
    public User(ElGamal gamal) {
        BigInteger q = gamal.getQ(), a = gamal.getA();

        BigInteger tempPrivateKey;
        do {
            tempPrivateKey = new BigInteger(q.bitLength(), secureRandom);
        } while(BI_ONE.compareTo(tempPrivateKey) >= 0
                || tempPrivateKey.compareTo(q.subtract(BI_TWO)) >= 0);

        privateKey = tempPrivateKey;
        publicKey = a.modPow(privateKey, q);
        this.gamal = gamal;
    }

    public BigInteger getPublicKey() {return publicKey;}

    public void print() {
        System.out.println("privateKey = " + privateKey + " publicKey = " + publicKey);
    }

    /**
     * Applies following constrain(s) when signing message:
     *      . 0 <= message <= q - 1
     *      . 1 < k < q − 1 and gcd(k, q − 1) = 1
     *      . s != 0
     * 
     * @param message message to be digitally signed
     * @return
     */
    public Signature sign(BigInteger message) throws Exception {
        BigInteger q = gamal.getQ(), qm1 = q.subtract(BI_ONE), a = gamal.getA();
        BigInteger hashedMessage = gamal.hash(message);
        BigInteger s1, s2, kinv;

        if (message.compareTo(BigInteger.ZERO) < 0 || message.compareTo(qm1) > 0) {
            throw new Exception("0 <= message <= " + qm1 + " given value is: " + message);
        }

        do {
            BigInteger k;
            do {
                k = new BigInteger(q.bitLength(), secureRandom);
            } while(BI_ONE.compareTo(k) >= 0 || k.compareTo(qm1) >= 0
                    || k.gcd(qm1).compareTo(BI_ONE) != 0);
    
            kinv = k.modInverse(q.subtract(BI_ONE));
            s1 = a.modPow(k, q);
            s2 = (hashedMessage.subtract(privateKey.multiply(s1))).multiply(kinv).mod(q.subtract(BI_ONE));
        } while(s2.compareTo(BigInteger.ZERO) == 0);

        return new Signature(s1, s2);
    }

    public boolean verify(Signature signature, BigInteger message, BigInteger otherPublicKey) {
        BigInteger q = gamal.getQ(), a = gamal.getA();
        BigInteger s1 = signature.getS1(), s2 = signature.getS2();
        BigInteger hashedMessage = gamal.hash(message);

        BigInteger v1 = a.modPow(hashedMessage, q);
        BigInteger v2 = otherPublicKey.modPow(s1, q).multiply(s1.modPow(s2, q)).mod(q);

        return v1.compareTo(v2) == 0;
    }

    public static void main(String[] args) throws Exception {
        int nBits = Integer.parseInt(args[0]);
        String hash = args[1];

        ElGamal gamal = new ElGamal(nBits, hash);
        gamal.print();

        BigInteger message;
        do {
            message = new BigInteger(nBits, new SecureRandom());
        } while(message.compareTo(gamal.getQ()) >= 0);
        System.out.println("message " + message);

        User user1 = new User(gamal);
        User user2 = new User(gamal);
        user1.print();

        System.out.println(user2.verify(user1.sign(message), message, user1.publicKey) ?
                                        "Verified" : "Not Verified");
    }
}