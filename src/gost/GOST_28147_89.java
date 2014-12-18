/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gost;

import java.util.Arrays;

/**
 *
 * @author Chernyshov
 */
public class GOST_28147_89 {

    private static final int KEY_SIZE = 32;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        byte[] theKey = "zdesdolzhno_bit_bolwe_31_simvola".getBytes();
        byte[] theMsg = "i want to encrypt this message1111111111".getBytes();
        byte[][] subKeys = getSubkeys(theKey);
        byte[] theCph = crypto(theMsg, subKeys, EncryptType.ENCRYPT);
        byte[] theDecr = crypto(theCph, subKeys, EncryptType.DECRYPT);
        System.out.println("Key: \n" + new String(theKey));
        System.out.println("Open message: \n" + new String(theMsg));
        System.out.println("Ecrypted message: \n" + new String(theCph));
//        System.out.println("Decrypted message: \n" + new String(theDecr));
    }

    public static byte[] crypto(byte[] originMessage, byte[][] subKeys, EncryptType type) {
        if (originMessage.length < 8) {
            throw new IllegalArgumentException("Message is less than 64 bits.");
        }
        byte[][] splittedMessage = ByteUtils.splitMessageTo64bits(originMessage, 8);
        byte[] resultMessage = new byte[]{};
        for (int i = 0; i < splittedMessage.length; i++) {
            byte[] message = splittedMessage[i];

            int blockSize = message.length;
            byte[] l = ByteUtils.selectBits(message, 0, blockSize / 2);
            byte[] r = ByteUtils.selectBits(message, blockSize / 2, blockSize / 2);
            int numOfSubKeys = subKeys.length;
            for (int k = 0; k < numOfSubKeys; k++) {
                byte[] rBackup = r;
                r = feistelFuction(r, type.equals(EncryptType.ENCRYPT) ? subKeys[k] : subKeys[numOfSubKeys - k - 1]);
                r = ByteUtils.doXORBytes(l, r);
                l = rBackup;
            }
            byte[] lr = ByteUtils.concatenateBits(r, blockSize / 2, l, blockSize / 2);

            resultMessage = ByteUtils.concatenateBits(resultMessage, resultMessage.length * 8, lr, blockSize);
        }

        return resultMessage;
    }

    private static byte[] feistelFuction(byte[] r, byte[] subKey) {
        byte[] cur = doHORin32(r, subKey);
        byte[] result = new byte[r.length];
        int offset = 0;
        while (offset < r.length) {
            int val = bytes2Dword(cur, 0);
            offset += 4;
        }

        return r;
    }

    private static byte[] doHORin32(byte[] a, byte[] b) {
        long res = 0;
        byte[] c = new byte[4];
        for (int i = 0, j = 3; i < 32; --j, i += 8) {
            res += (a[j] + b[j]) << i;
        }

        for (int i = 0, j = 3; i < 32; --j, i += 8) {
            c[j] = (byte) ((byte) res >> i);
        }

        return c;
    }

    private static int bytes2Dword(byte[] input, int offset) {
        if (offset + 4 > input.length) {
            throw new IllegalArgumentException();
        }
        return (int) ((input[offset + 3] << 24) ^ (input[offset + 2] << 16) ^ (input[offset + 1] << 8) ^ (input[offset]));
    }

    private static byte[][] getSubkeys(byte[] key) {
        if (key.length < KEY_SIZE) {
            throw new IllegalArgumentException("Key is less than 32 byte");
        }
        byte[][] res = new byte[32][4];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(key, 4 * i, res[i], 0, 4);
        }
        for (int i = 8, j = 0; i < 24; i++) {
            System.arraycopy(res[j++], 0, res[i], 0, res[i].length);
        }
        for (int i = 24, j = 0; i < 32; i++) {
            System.arraycopy(res[7 - j++], 0, res[i], 0, res[i].length);
        }
        return res;
    }

    public static enum EncryptType {

        ENCRYPT,
        DECRYPT;
    }

    void GOST_28147_89(byte[] src, byte[] dst, byte[] key, boolean direction) {
        int len = src.length, blocks;
        int N1, N2, SM1, SM2 = 0;
        int[] key_array = new int[KEY_SIZE / 4];
        int i, B_i, R_i;
        int[][] Key_Sequences = new int[][]{{0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0}};
        int[][] S = new int[][]{
            {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
            {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
            {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
            {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
            {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
            {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
            {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
            {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
        };

        for (i = 0; i < (KEY_SIZE / 4); ++i) {
            key_array[i] = (key[4 * i] << 24) + (key[1 + 4 * i] << 16) + (key[2 + 4 * i] << 8) + key[3 + 4 * i];
        }

        blocks = src.length / 8;

        for (B_i = 0; B_i < blocks; ++B_i) {

//            N1 =  * ((int) src + B_i * 2 + 1);
//            N2 =  * ((int*)src + B_i * 2);

        for (R_i = 0; R_i < 32; ++R_i) {
                SM1 = N1 + key_array[7 - Key_Sequences[direction == true ? 1 : 0][R_i]];

                SM2 = 0;
                for (i = 0; i < 8; ++i) {
                    SM2 |= S[i][(SM1 >> (i * 4)) & 0xF] << (i * 4);
                }
                SM1 = SM2;

                SM1 = (SM1 >> 21) | (SM1 << 11);
                SM2 = SM1 ^ N2;

                if (R_i == 32 - 1) {
                    break;
                }
                N2 = N1;
                N1 = SM2;
            }

            N2 = SM2;

            for (i = 0; i < 4; ++i) {
                dst[4 + 8 * B_i + i] = (byte) ((N1 >> (8 * i)) & 0xFF);
                dst[8 * B_i + i] = (byte) ((N2 >> (8 * i)) & 0xFF);
            }
            dst[4 + 8 * B_i + i] = 0;
        }
    }

}
