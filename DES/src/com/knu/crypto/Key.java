package com.knu.crypto;

import sun.security.util.BitArray;
import static com.knu.crypto.Helper.*;


public class Key {
    private BitArray newKey = new BitArray(64);
    private BitArray[] keys = new BitArray[16];

    public Key(String keyS) {
        if (keyS.length() != 7)
            throw new IllegalArgumentException("Key has incorrect size");

        BitArray key = new BitArray(56, keyS.getBytes());
        for (int i = 0; i < 8; i++) {
            boolean temp = true;
            for (int j = 0; j < 7; j++) {
                newKey.set(i * 8 + j, key.get(i * 7 + j));
                temp = temp ^ key.get(i * 7 + j);
            }
            newKey.set(i * 7 + 7, temp);
        }
        initSubKeys();
    }

    private void leftShift(BitArray bitArray, int a) {
        while (a != 0) {
            a--;
            boolean b = bitArray.get(0);

            for (int i = 0; i < 27; i++) {
                bitArray.set(i, bitArray.get(i + 1));
            }
            bitArray.set(27, b);
        }
    }


    private void initSubKeys() {
        BitArray C = new BitArray(28), D = new BitArray(28);

        for (int i = 0; i < 28; i++) {
            C.set(i, newKey.get(replaseTableC[i]));
            D.set(i, newKey.get(replaseTableD[i]));
        }

        for (int i = 0; i < 16; i++) {
            leftShift(C, shiftTable[i]);
            leftShift(D, shiftTable[i]);
            keys[i] = new BitArray(48);

            for (int j = 0; j < 48; j++) {
                if (keyCreateTable[i] < 28)
                    keys[i].set(i, C.get(keyCreateTable[i]));
                else
                    keys[i].set(i, D.get(keyCreateTable[i] - 28));
            }
        }

    }

    public BitArray getKey(int i){
        return keys[i];
    }

}