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
    public enum ClobberMode {NONE, UNIQUE, OVERWRITE;}
    
    public static class Clobbered {
        public File    file;
        public boolean matched;
        public Clobbered (File file, boolean matched) {
            this.file    = file;
            this.matched = matched;
        }
    }
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
                in  = new BufferedInputStream(url.openStream());
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

    public static byte[] read(String f) throws IOException {
        return read(new File(f));
    }
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

    public static void write(String content, String f, ClobberMode mode) throws IOException {
        write(content, new File(f), mode);
    }
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

    public static byte[] md5(String f) throws Exception {
        return md5(new File(f));
    }
    public static byte[] md5(File f) throws Exception {
        return hash(f, "MD5");
    }
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
    public static boolean hashMatches(File f, String alg, byte[] hash) {
        if (f!=null && alg!=null && hash!=null && hash.length>0) {
            try {
                byte[] fhash = hash(f, alg);
                return Arrays.equals(fhash, hash);
            } catch (Exception ignore) {}
        }
        return false;
    }
    public static byte[] hashOrNull(File f, String alg) {
        try {
            return hash(f, alg);
        } catch (Exception ignore) {}
        return null;
    }

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
