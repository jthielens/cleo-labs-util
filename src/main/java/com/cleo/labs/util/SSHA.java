package com.cleo.labs.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class SSHA {

    public static final  String       TAG    = "{SSHA}";
    public static final  int          HASHLEN = 20;
    public static final  int          SALTLEN = 4;
    private static final SecureRandom random = new SecureRandom();

    public static byte[] hashbytes(String password) {
        byte[] salt = new byte[SALTLEN];
        random.nextBytes(salt);
        return hashbytes(password, salt);
    }

    public static byte[] hashbytes(String password, byte[] salt) {
        byte[] passbytes = password.getBytes();
        byte[] buffer    = Arrays.copyOf(passbytes, passbytes.length+salt.length);
        System.arraycopy(salt, 0, buffer, passbytes.length, salt.length);
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        byte[] hash = md.digest(buffer);
        byte[] result = Arrays.copyOf(hash, hash.length+salt.length);
        System.arraycopy(salt, 0, result, hash.length, salt.length);
        return result;
    }

    public static String hash(String password) {
        return TAG+Base64.getEncoder().encode(hashbytes(password));
    }

    public static boolean verify(String password, String encoded) {
        if (!encoded.startsWith(TAG)) {
            return false; // doesn't start with TAG
        }
        byte[] encbytes;
        try {
            encbytes = Base64.getDecoder().decode(encoded.substring(TAG.length()));
        } catch (IllegalArgumentException e) {
            return false; // doesn't look base64 encoded
        }
        if (encbytes.length!=HASHLEN+SALTLEN) {
            return false; // should be 20 bytes of hash + 4 bytes of salt
        }
        byte[] salt = Arrays.copyOfRange(encbytes, HASHLEN, HASHLEN+SALTLEN);
        byte[] passwordhash = hashbytes(password, salt);
        return Arrays.equals(encbytes, passwordhash);
    }

    private SSHA() { }

    public static void main(String[] args) {
        System.out.println(hash("cleo"));
        String f = hash("cleo");
        System.out.println(verify("cleo", f));
    }
}
