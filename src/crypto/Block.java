package crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Timestamp;

public class Block {
    private int index;
    private String hash;
    private String previousHash;
    private String data;
    private Timestamp timeStamp;

    public Block(int index, String hash, String previousHash, String data, Timestamp timeStamp) {
        this.index = index;
        this.hash = hash;
        this.previousHash = previousHash;
        this.data = data;
        this.timeStamp = timeStamp;
    }

    public int getIndex() {
        return index;
    }

    public String getHash() {
        return hash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String getData() {
        return data;
    }

    public Timestamp getTimeStamp() {
        return timeStamp;
    }

    public String calculateHash() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = messageDigest.digest((index+hash+previousHash+data+timeStamp)
                .getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
        for (int i = 0; i < encodedHash.length; i++) {
            String hex = Integer.toHexString(0xff & encodedHash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
