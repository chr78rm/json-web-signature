package de.christofreichardt.json.websignature;

import java.util.Arrays;

/**
 *
 * @author Christof Reichardt
 */
public class JWSUtils {

    static String formatBytes(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            stringBuilder.append(Byte.toUnsignedInt(bytes[i]));
            if (i < bytes.length - 1) {
                stringBuilder.append(", ");
            }
        }
        
        return stringBuilder.toString();
    }
    
    static byte[] skipSurplusZeroes(byte[] bytes, int length) {
        int start = 0;
        while (bytes[start] == 0 && bytes.length - start > length) {
            start++;
        }
        
        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    static byte[] skipLeadingZeroes(byte[] bytes) {
        int start = 0;
        while (bytes[start] == 0 && bytes.length - start > 1) {
            start++;
        }

        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    static byte[] fillMissingZeroes(byte[] bytes, int length) {
        if (bytes.length >= length) {
            return bytes;
        }
        byte[] dest = new byte[length];
        System.arraycopy(bytes, 0, dest, length - bytes.length, bytes.length);

        return dest;
    }

    static byte[] alignBytes(byte[] bytes, int length) {
        bytes = skipSurplusZeroes(bytes, length);
        bytes = fillMissingZeroes(bytes, length);
        if (bytes.length != length) {
            throw new IllegalArgumentException();
        }
        return bytes;
    }
}
