/*
 * Copyright (C) 2022, Christof Reichardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.christofreichardt.json.webkey;

import java.util.Arrays;

/**
 * Some low level utility procedures for handling raw bytes.
 *
 * @author Christof Reichardt
 */
public class JsonWebKeyUtils {

    private JsonWebKeyUtils() {
    }

    /**
     * Interpretes the given bytes as unsigned integers and concatenates them into a comma separated string.
     *
     * @param bytes the given raw bytes.
     * @return a formatted string containf the bytes as comma separated unsigned integers.
     */
    public static String formatBytes(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            stringBuilder.append(Byte.toUnsignedInt(bytes[i]));
            if (i < bytes.length - 1) {
                stringBuilder.append(", ");
            }
        }
        
        return stringBuilder.toString();
    }

    /**
     * Cuts surplus zeroes from the beginning of the byte array.
     *
     * @param bytes the given raw bytes.
     * @param length the favored length.
     * @return a new byte array without surplus zeroes and the given minimal length.
     */
    public static byte[] skipSurplusZeroes(byte[] bytes, int length) { // TODO: Consider the usage of alignBytes(byte[] bytes, int length) instead for all its appearances
        int start = 0;
        while (bytes[start] == 0 && bytes.length - start > length) {
            start++;
        }
        
        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    /**
     * Cuts leading zeroes from the beginning of the byte array. A byte array made up exclusively of zeroes will be cut down to a single byte.
     *
     * @param bytes the given raw bytes.
     * @return a byte array without leading zeroes.
     */
    public static byte[] skipLeadingZeroes(byte[] bytes) {
        int start = 0;
        while (bytes[start] == 0 && bytes.length - start > 1) {
            start++;
        }

        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    /**
     * Fills in missing zeroes at the begin of a byte array if required. An array of size greater than the given length remains untouched.
     *
     * @param bytes the given raw bytes.
     * @param length the favored length.
     * @return a byte array with leading zeroes if required to match the favord length.
     */
    public static byte[] fillMissingZeroes(byte[] bytes, int length) {
        if (bytes.length >= length) {
            return bytes;
        }
        byte[] dest = new byte[length];
        System.arraycopy(bytes, 0, dest, length - bytes.length, bytes.length);

        return dest;
    }

    /**
     * Takes the given raw bytes and tries to return an equivalent byte array with the favored length by skipping surplus zeroes or filling in missing zeroes.
     * If that doesn't work an IllegalArgumentException is thrown.
     *
     * @param bytes the given raw bytes.
     * @param length the favored length.
     * @throws IllegalArgumentException if the favored length couldn't be matched.
     * @return a byte array with the desired length.
     */
    public static byte[] alignBytes(byte[] bytes, int length) {
        bytes = skipSurplusZeroes(bytes, length);
        bytes = fillMissingZeroes(bytes, length);
        if (bytes.length != length) {
            throw new IllegalArgumentException();
        }
        return bytes;
    }
}
