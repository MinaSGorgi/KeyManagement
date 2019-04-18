package core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Represents a user of the ElGamal algorithm for Digital Signature. Implemented
 * from "Cryptography and Network Security" Fifth Edition by William Stallings.
 * 
 * @author Mina Sami
 * @version 1.0
 */
class User {
    private final static SecureRandom secureRandom = new SecureRandom();
    private final static BigInteger BI_ONE = BigInteger.ONE;
    private final static BigInteger BI_TWO = new BigInteger("2");

    private final BigInteger gamalPrivateKey, gamalPublicKey;
    private final ElGamal gamal;
    private final KeyPair rsaKeys;
    private final Cipher rsaCipher;

    /**
     * Applies following constrain(s) when generating user keys:
     * . 1 < privateKey < q − 2.
     */
    public User(ElGamal gamal) throws Exception {
        // Initialize RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(gamal.getNBits());
        rsaKeys = keyPairGenerator.genKeyPair();
        rsaCipher = Cipher.getInstance("RSA");

        // Initialize ElGamal Keys
        BigInteger q = gamal.getQ(), a = gamal.getA();

        BigInteger tempPrivateKey;
        do {
            tempPrivateKey = new BigInteger(q.bitLength(), secureRandom);
        } while (BI_ONE.compareTo(tempPrivateKey) >= 0 || tempPrivateKey.compareTo(q.subtract(BI_TWO)) >= 0);

        gamalPrivateKey = tempPrivateKey;
        gamalPublicKey = a.modPow(gamalPrivateKey, q);
        this.gamal = gamal;
    }

    public BigInteger getGamalPublicKey() {
        return gamalPublicKey;
    }

    public PublicKey getRSAPublicKey() {
        return rsaKeys.getPublic();
    }

    public void print() {
        System.out.println("gamalPrivateKey = " + gamalPrivateKey + " gamalPublicKey = " + gamalPublicKey);
    }

    public BigInteger encrypt(BigInteger message, PublicKey otherRSAPublicKey) throws Exception {
        // TODO: change to accepting strings instead
        rsaCipher.init(Cipher.ENCRYPT_MODE, otherRSAPublicKey);
        return new BigInteger(rsaCipher.doFinal(message.toByteArray()));
    }

    public BigInteger decrypt(BigInteger ecryptedMessage) throws Exception {
        // TODO: change to accepting strings instead
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
        return new BigInteger(rsaCipher.doFinal(ecryptedMessage.toByteArray()));
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
        // TODO: change to accepting strings instead
        BigInteger q = gamal.getQ(), qm1 = q.subtract(BI_ONE), a = gamal.getA();
        BigInteger hashedMessage = gamal.hash(message);
        BigInteger s1, s2, kinv;

        /*if (message.compareTo(BigInteger.ZERO) < 0 || message.compareTo(qm1) > 0) {
            throw new Exception("0 <= message <= " + qm1 + " given value is: " + message);
        }*/

        do {
            BigInteger k;
            do {
                k = new BigInteger(q.bitLength(), secureRandom);
            } while(BI_ONE.compareTo(k) >= 0 || k.compareTo(qm1) >= 0
                    || k.gcd(qm1).compareTo(BI_ONE) != 0);
    
            kinv = k.modInverse(q.subtract(BI_ONE));
            s1 = a.modPow(k, q);
            s2 = (hashedMessage.subtract(gamalPrivateKey.multiply(s1))).multiply(kinv).mod(q.subtract(BI_ONE));
        } while(s2.compareTo(BigInteger.ZERO) == 0);

        return new Signature(s1, s2);
    }

    public boolean verify(Signature signature, BigInteger message, BigInteger otherPublicKey) {
        // TODO: change to accepting strings instead
        BigInteger q = gamal.getQ(), a = gamal.getA();
        BigInteger s1 = signature.getS1(), s2 = signature.getS2();
        BigInteger hashedMessage = gamal.hash(message);

        BigInteger v1 = a.modPow(hashedMessage, q);
        BigInteger v2 = otherPublicKey.modPow(s1, q).multiply(s1.modPow(s2, q)).mod(q);

        return v1.compareTo(v2) == 0;
    }

    public Packet packPacket(BigInteger message, PublicKey otherRSAPublicKey) throws Exception {
        BigInteger encryptedMessage = encrypt(message, otherRSAPublicKey);
        return new Packet(encryptedMessage, sign(encryptedMessage));
    }

    public BigInteger unpackPacket(Packet packet, BigInteger otherGamalPublicKey) throws Exception {
        BigInteger decryptedMessage = decrypt(packet.getMessage());
        boolean verified = verify(packet.getSignature(), packet.getMessage(), otherGamalPublicKey);
        if(!verified) {
            throw new Exception("Signature not verified!");
        }

        return decryptedMessage;
    }

    public static void main(String[] args) throws Exception {
        String hash = args[0];
        int nBits = Integer.parseInt(args[1]);
        BigInteger message = new BigInteger(args[2]);

        ElGamal gamal = new ElGamal(nBits, hash);
        User user1 = new User(gamal);
        User user2 = new User(gamal);
        User user3 = new User(gamal);

        System.out.println("Sucess Test...");
        Packet packet = user2.packPacket(message, user1.getRSAPublicKey());
        BigInteger decryptedMessage = user1.unpackPacket(packet, user2.getGamalPublicKey());
        System.out.println("decrypted message = " + decryptedMessage);
        System.out.println(decryptedMessage.equals(message) ? "Dectypted Succesfully" : "Failed" );

        System.out.println();

        System.out.println("Gamal Fail Test...");
        Packet packet1 = user2.packPacket(message, user1.getRSAPublicKey()); 
        try {
            user1.unpackPacket(packet1, user3.getGamalPublicKey());
        } catch(Exception e) {
            e.printStackTrace();
        }   
    }
}