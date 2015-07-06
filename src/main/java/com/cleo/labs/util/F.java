package com.cleo.labs.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.util.Arrays;

public class F {
    /**
     * Describes the intended overwrite behavior when a file is created.
     * <ul>
     * <li>{@code NONE} throws an error</li>
     * <li>{@code UNIQUE} causes a new unique filename to be created by appending a [n] suffix.</li>
     * <li>{@code OVERWRITE} replaces the existing file.</li>
     * </ul>
     */
    public enum ClobberMode {NONE, UNIQUE, OVERWRITE;}
    
    /**
     * A "case" class describing a file clobbering result, including:
     * <ul>
     * <li>{@code file} the {@link File} that was created/written/matched</li>
     * <li>{@code matched} is {@code true} if the existing {@link File} matched hashes and was retained</li>
     * </ul>
     */
    public static class Clobbered {
        public File    file;
        public boolean matched;
        public Clobbered (File file, boolean matched) {
            this.file    = file;
            this.matched = matched;
        }
    }
    /**
     * Given an intended destination {@link File} and an existing {@code hash} (and the
     * algorithm used to compute it), returns a {@link Clobbered} result indicating
     * (a) whether the existing file matched the hash and should be used, and
     * (b) the {@link File} to be used as the destination.  If an existing file was not
     * matched, a new empty file will have been created (or an {@link IOException} thrown
     * if the file can't be created or clobbered).
     * @param dst the intended destination {@link File}
     * @param mode the {@link ClobberMode} policy
     * @param alg the hash algorithm
     * @param hash the hash value (may be {@code null})
     * @return a {@link Clobbered} result
     * @throws IOException
     */
    private static Clobbered clobber(File dst, ClobberMode mode, String alg, byte[] hash) throws IOException {
        boolean matched = false;
        if (dst.exists()) {
            if (hashMatches(dst, alg, hash)) {
                matched = true;
            } else if (mode==ClobberMode.UNIQUE) {
                for (int i=1;;i++) {
                    File unique = new File(dst.getAbsolutePath()+"["+i+"]");
                    if (unique.exists()) {
                        if (hashMatches(unique, alg, hash)) {
                            matched = true;
                            break;
                        }
                    } else {
                        dst = unique;
                        break;
                    }
                }
            } else if (mode==ClobberMode.NONE) {
                throw new IOException("copy destination already exists");
            }
        }
        if (!dst.exists()) {
            dst.createNewFile();
        }
        return new Clobbered(dst, matched);
    }

    /**
     * Conditionally copies {@link File} {@code src} to {@code dst} subject to the
     * {@link ClobberMode} clobbering policy and an MD5 hash comparison if {@code dst}
     * already exists.
     * Note that {@code dst} may be a directory, in which case it is resolved by
     * appending {@code src.getName()}.
     * @param src the source file, which must exist and be a normal file
     * @param dst the intended destination file (or directory), which may or may not exist already
     * @param mode the {@link ClobberMode} policy
     * @return a {@link Clobbered} indicating the match status and actual destination file
     * @throws IOException
     */
    public static Clobbered copy(File src, File dst, ClobberMode mode) throws IOException {
        if (!src.exists()) {
            throw new IOException("copy source does not exist");
        } else if (!src.isFile()) {
            throw new IOException("copy source must be a normal file");
        }
        if (dst.isDirectory()) {
            dst = new File(dst, src.getName());
        }
        Clobbered result = clobber(dst, mode, "MD5", hashOrNull(src, "MD5"));
        if (!result.matched) {
            FileChannel schannel = null;
            FileChannel dchannel = null;
    
            try {
                schannel = new FileInputStream(src).getChannel();
                dchannel = new FileOutputStream(dst).getChannel();
                dchannel.transferFrom(schannel, 0, schannel.size());
            } finally {
                if (schannel != null) schannel.close();
                if (dchannel != null) dchannel.close();
            }
        }
        return result;
    }

    /**
     * Conditionally downloads {@link URL} {@code src} to {@code dst} subject to the
     * {@link ClobberMode} clobbering policy and a hash comparison if {@code dst}
     * already exists.
     * Note that {@code dst} may be a directory, in which case it is resolved by
     * appending the final path element parsed from {@code src}.
     * @param src the source {@link URL} as a {@link String}
     * @param dst the intended destination file (or directory), which may or may not exist already
     * @param alg the hash algorithm
     * @param hash the hash for comparison (may be {@code null})
     * @param mode the {@link ClobberMode} policy
     * @return a {@link Clobbered} indicating the match status and actual destination file
     * @throws Exception
     */
    public static Clobbered download(String src, File dst, String alg, byte[] hash, ClobberMode mode) throws Exception {
        URL url = new URL(src);
        if (dst.isDirectory()) {
            // figure out the intended name
            String[] names = url.getPath().split("/"); // trailing / is ignored by split
            String name = names.length>0 ? names[names.length-1] : url.getHost();
            dst = new File(dst, name);
        }
        Clobbered result = clobber(dst, mode, alg, hash);
        if (!result.matched) {
            BufferedInputStream  in  = null;
            BufferedOutputStream out = null;
            try {
                URLConnection u = new URL(src).openConnection();
                u.setRequestProperty("User-Agent", "curl/7.37.1");
                u.setUseCaches(false);
                in = new BufferedInputStream(u.getInputStream());
                out = new BufferedOutputStream(new FileOutputStream(result.file));
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    out.write(buf, 0, n);
                }
            } finally {
                if (in !=null) in.close();
                if (out!=null) out.close();
            }
        }
        return result;
    }

    /**
     * Downloads {@link URL} {@code src} and returns the content as a {@code byte[]},
     * or {@code null} in case of an error (eating exceptions in the process).
     * @param src the {@link URL} to download
     * @return the content or {@code null}
     */
    public static byte[] download(String src) {
        BufferedInputStream in = null;
        ByteArrayOutputStream out = null;
        try {
            URLConnection u = new URL(src).openConnection();
            u.setRequestProperty("User-Agent", "curl/7.37.1");
            u.setUseCaches(false);
            in = new BufferedInputStream(u.getInputStream());
            out = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (IOException abort) {
        } finally {
            if (in !=null) try {in.close();} catch (IOException ignore) {}
            if (out!=null) try {out.close();} catch (IOException ignore) {}
        }
        return null;
    }

    /**
     * Reads {@link File} named {@code f} and returns the contents as a {@code byte[]}.
     * Throws an Exception in case of error.
     * @param f the name of the {@link File} to read
     * @return the file content
     * @throws IOException
     */
    public static byte[] read(String f) throws IOException {
        return read(new File(f));
    }
    /**
     * Reads {@link File} {@code f} and returns the contents as a {@code byte[]}.
     * Throws an Exception in case of error.
     * @param f the {@link File} to read
     * @return the file content
     * @throws IOException
     */
    public static byte[] read(File f) throws IOException {
        byte buf[] = new byte[(int)f.length()];
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            fis.read(buf);
        } finally {
            if (fis!=null) fis.close();
        }
        return buf;
    }

    /**
     * Writes {@link String} {@code content} to {@link File} named {@code f}, subject to
     * the overwrite {@link ClobberMode} policy {@code mode}.
     * @param content the content {@link String}
     * @param f the name of destination {@link File}
     * @param mode the overwrite policy
     * @throws IOException if something goes wrong
     */
    public static void write(String content, String f, ClobberMode mode) throws IOException {
        write(content, new File(f), mode);
    }
    /**
     * Writes {@link String} {@code content} to {@link File} {@code f}, subject to
     * the overwrite {@link ClobberMode} policy {@code mode}.
     * @param content the content {@link String}
     * @param f the destination {@link File}
     * @param mode the overwrite policy
     * @throws IOException if something goes wrong
     */
    public static void write(String content, File f, ClobberMode mode) throws IOException {
        f = clobber(f, mode, null, null).file;
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f);
            fos.write(content.getBytes());
        } finally {
           if (fos!=null) fos.close();
        }
    }

    /**
     * Returns the MD5 hash of the contents of {@link File} named {code f}.
     * @param f the name of the {@code File} to read
     * @return the MD5 hash
     * @throws Exception in caes of error
     */
    public static byte[] md5(String f) throws Exception {
        return md5(new File(f));
    }
    /**
     * Returns the MD5 hash of the contents of {@link File} {code f}.
     * @param f the {@code File} to read
     * @return the MD5 hash
     * @throws Exception in case of error
     */
    public static byte[] md5(File f) throws Exception {
        return hash(f, "MD5");
    }
    /**
     * Returns the hash of the contents of {@link File} {code f}
     * using the indicated algorithm.
     * @param f the {@code File} to read
     * @param alg the hash algorithm to use
     * @return the hash
     * @throws Exception in case of error
     */
    public static byte[] hash(File f, String alg) throws Exception {
        MessageDigest   md  = MessageDigest.getInstance(alg);
        FileInputStream fis = null;
        byte[]          buf = new byte[65536];
        try {
            fis = new FileInputStream(f);
            int n;
            while ((n = fis.read(buf)) >= 0) {
                md.update(buf, 0, n);
            }
        } finally {
            if (fis!=null) fis.close();
        }
        return md.digest();
    }
    /**
     * Return {@code true} if the hash of the contents of {@link File} {@code f}
     * matches {@code hash} using algorithm {@code alg}.  Returns {@code} false
     * otherwise, including if any Exceptions occur during the process.
     * @param f the {@link File} to read
     * @param alg the hash algorithm to use
     * @param hash the expected hash value
     * @return {@code true} if the hash matches
     */
    public static boolean hashMatches(File f, String alg, byte[] hash) {
        if (f!=null && alg!=null && hash!=null && hash.length>0) {
            try {
                byte[] fhash = hash(f, alg);
                return Arrays.equals(fhash, hash);
            } catch (Exception ignore) {}
        }
        return false;
    }
    /**
     * Returns the hash of {@link File} {@code f} using algorithm {@code alg},
     * or null if any error or Exception occurs.
     * @param f the {@link File} to read
     * @param alg the hash algorithm to use
     * @return the hash value or {@code null}
     */
    public static byte[] hashOrNull(File f, String alg) {
        try {
            return hash(f, alg);
        } catch (Exception ignore) {}
        return null;
    }

    /**
     * Formats a {@code byte[]} array as a hexadecimal {@link String}.
     * @param bytes the {@code byte[]}s to format
     * @return the formatted {@link String}, or {@code null} if {@code bytess} is {@code null}
     */
    public static String hex(byte[] bytes) {
        if (bytes==null) return null;
        StringBuffer s = new StringBuffer();
        for (byte b : bytes) {
            s.append(String.format("%02x", b));
        }
        return s.toString();
    }
    private static int[] HEX = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00-0F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10-1F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20-2F
                                           0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, // 30-3F
                                           0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 40-4F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 50-5F
                                           0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 60-6F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 70-7F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 80-8F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 90-9F
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A0-AF
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // B0-BF
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // C0-CF
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // D0-DF
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // E0-EF
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};// F0-FF
    /**
     * Converts a hexadecimal {@link String} into a binary {@code byte[]} array.  If the
     * string is not of even length or is not 100% hexadecimal (or is {@code null},
     * returns {@code null}.  Both upper and lower case A-F are accepted.
     * @param s the {@link String} to convert
     * @return the converted {@code byte[]}, or {@code null}
     */
    public static byte[] hex(String s) {
        if (s==null || s.length() % 2 != 0 || s.contains("[^0-9a-fA-F]")) {
            return null;
        } else {
            byte[] source = s.getBytes();
            byte[] result = new byte[s.length() / 2];
            for (int i=0; i<result.length; i++) {
                result[i] = (byte)((HEX[source[2*i]]<<4)+HEX[source[2*i+1]]);
            }
            return result;
        }
    }
}
