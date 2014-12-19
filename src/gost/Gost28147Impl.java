/*
 * Gost28147Transform.java
 * 
 * Created: 19.12.2014
 * 
 * Copyright (c) ExpertPB 2014
 * All information contained herein is, and remains the property of
 * ExpertPB and its suppliers, if any.
 */
package gost;

/**
 *
 * @author Roman Chernyshev
 */
public class Gost28147Impl{

    private static byte[] s8 = new byte[]{0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC};
    private static byte[] s7 = new byte[]{0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC};
    private static byte[] s6 = new byte[]{0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE};
    private static byte[] s5 = new byte[]{0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2};
    private static byte[] s4 = new byte[]{0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3};
    private static byte[] s3 = new byte[]{0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB};
    private static byte[] s2 = new byte[]{0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9};
    private static byte[] s1 = new byte[]{0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3};

    private static int[] s87;
    private static int[] s65;
    private static int[] s43;
    private static int[] s21;

    private static final int KEY_SIZE = 256;

    static void init(){
        s87 = new int[256];
        s65 = new int[256];
        s43 = new int[256];
        s21 = new int[256];

        int i = 0;
        for (int a = 0; a < 16; ++a) {
            int ax = ((int) (s2[a] << 15));
            int bx = (int) (s4[a] << 23);
            int cx = (int) s6[a];
            cx = (cx >> 1) | (cx << 31);
            int dx = (int) (s8[a] << 7);

            for (int b = 0; b < 16; ++b) {
                s21[i] = ax | (int) (s1[b] << 11);
                s43[i] = bx | (int) (s3[b] << 19);
                s65[i] = cx | (int) (s5[b] << 27);
                s87[i++] = dx | (int) (s7[b] << 3);
            }
        }
    }

    private int[] key;

    public Gost28147Impl(byte[] key) {
        init();
        if ((key.length << 3) != KEY_SIZE) {
            System.out.println("keySize = " + KEY_SIZE + "key = " + (key.length << 3));
            throw new RuntimeException("Key size doesn't match key");
        }

        this.key = new int[8];
        for (int i = 0, j = 0; i < 8; i++, j += 4) {
            this.key[i] = ((int) key[j])
                    | (((int) key[j + 1]) << 8)
                    | (((int) key[j + 2]) << 16)
                    | (((int) key[j + 3]) << 24);
        }
    }

    public void ECB(byte[] input, byte[] output, boolean encrypt) {
        int left = ((int) input[0]) | ((int) input[1] << 8) | ((int) input[2] << 16) | ((int) input[3] << 24);
        int right = ((int) input[4]) | ((int) input[5] << 8) | ((int) input[6] << 16) | ((int) input[7] << 24);

        IntWrapper wrap = ECB(left, right, key, encrypt);
        left = wrap.left;
        right = wrap.right;

        output[0] = (byte) left;
        output[1] = (byte) (left >> 8);
        output[2] = (byte) (left >> 16);
        output[3] = (byte) (left >> 24);

        output[4] = (byte) right;
        output[5] = (byte) (right >> 8);
        output[6] = (byte) (right >> 16);
        output[7] = (byte) (right >> 24);
    }

    private IntWrapper ECB(int left, int right, int[] key, boolean encrypt) {
        if (encrypt) {
            left ^= CipherFunction((right + key[0]));
            right ^= CipherFunction((left + key[1]));
            left ^= CipherFunction((right + key[2]));
            right ^= CipherFunction((left + key[3]));
            left ^= CipherFunction((right + key[4]));
            right ^= CipherFunction((left + key[5]));
            left ^= CipherFunction((right + key[6]));
            right ^= CipherFunction((left + key[7]));

            left ^= CipherFunction((right + key[0]));
            right ^= CipherFunction((left + key[1]));
            left ^= CipherFunction((right + key[2]));
            right ^= CipherFunction((left + key[3]));
            left ^= CipherFunction((right + key[4]));
            right ^= CipherFunction((left + key[5]));
            left ^= CipherFunction((right + key[6]));
            right ^= CipherFunction(left + key[7]);

            left ^= CipherFunction(right + key[0]);
            right ^= CipherFunction(left + key[1]);
            left ^= CipherFunction(right + key[2]);
            right ^= CipherFunction(left + key[3]);
            left ^= CipherFunction(right + key[4]);
            right ^= CipherFunction(left + key[5]);
            left ^= CipherFunction(right + key[6]);
            right ^= CipherFunction(left + key[7]);

            left ^= CipherFunction(right + key[7]);
            right ^= CipherFunction(left + key[6]);
            left ^= CipherFunction(right + key[5]);
            right ^= CipherFunction(left + key[4]);
            left ^= CipherFunction(right + key[3]);
            right ^= CipherFunction(left + key[2]);
            left ^= CipherFunction(right + key[1]);
            right ^= CipherFunction(left + key[0]);
        } else {
            left ^= CipherFunction(right + key[0]);
            right ^= CipherFunction(left + key[1]);
            left ^= CipherFunction(right + key[2]);
            right ^= CipherFunction(left + key[3]);
            left ^= CipherFunction(right + key[4]);
            right ^= CipherFunction(left + key[5]);
            left ^= CipherFunction(right + key[6]);
            right ^= CipherFunction(left + key[7]);

            left ^= CipherFunction(right + key[7]);
            right ^= CipherFunction(left + key[6]);
            left ^= CipherFunction(right + key[5]);
            right ^= CipherFunction(left + key[4]);
            left ^= CipherFunction(right + key[3]);
            right ^= CipherFunction(left + key[2]);
            left ^= CipherFunction(right + key[1]);
            right ^= CipherFunction(left + key[0]);

            left ^= CipherFunction(right + key[7]);
            right ^= CipherFunction(left + key[6]);
            left ^= CipherFunction(right + key[5]);
            right ^= CipherFunction(left + key[4]);
            left ^= CipherFunction(right + key[3]);
            right ^= CipherFunction(left + key[2]);
            left ^= CipherFunction(right + key[1]);
            right ^= CipherFunction(left + key[0]);

            left ^= CipherFunction(right + key[7]);
            right ^= CipherFunction(left + key[6]);
            left ^= CipherFunction(right + key[5]);
            right ^= CipherFunction(left + key[4]);
            left ^= CipherFunction(right + key[3]);
            right ^= CipherFunction(left + key[2]);
            left ^= CipherFunction(right + key[1]);
            right ^= CipherFunction(left + key[0]);
        }

        int temp = left;
        left = right;
        right = temp;
        return new IntWrapper(left, right);
    }

    private int CipherFunction(int xx) {
        return s21[xx & 0xff] | s43[(xx << 8) & 0xff] | s65[(xx << 16) & 0xff] | s87[(xx << 24) & 0xff];
    }

    private class IntWrapper {

        public int left;
        public int right;

        public IntWrapper(int left, int right) {
            this.left = left;
            this.right = right;
        }

    }
}
