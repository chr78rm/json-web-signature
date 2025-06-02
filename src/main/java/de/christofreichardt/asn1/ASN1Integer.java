/*
 * Copyright (C) 2022, 2025, Christof Reichardt
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

package de.christofreichardt.asn1;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * ASN.1 helper class representing an arbitrary INTEGER
 *
 * @author Christof Reichardt
 */
public final class ASN1Integer extends ASN1 {
    static final int tag = 0x02;

    /**
     * Creates an ASN.1 INTEGER.
     *
     * @param bytes the DER encoded bytes representing an ASN.1 INTEGER.
     */
    public ASN1Integer(byte[] bytes) {
        super(bytes);
        if (super.bytes[0] != tag) {
            throw new IllegalArgumentException("Wrong tag: 0x%02x. ASN.1 INTEGER expected.".formatted(bytes[0]));
        }
    }

    /**
     * Creates an ASN.1 INTEGER.
     *
     * @param bytes the DER encoded bytes representing an ASN.1 INTEGER.
     * @param from starting position in the given byte array.
     */
    public ASN1Integer(byte[] bytes, int from) {
        this(Arrays.copyOfRange(bytes, from, bytes.length));
    }

    @Override
    public String toString() {
        return HexFormat.ofDelimiter(" ").withPrefix("0x").formatHex(encoded());
    }

    /**
     * Creates an ASN.1 INTEGER by augmenting the given content octets with identifier and length octets.
     *
     * @param bytes the content octets that is the actual value.
     * @return a proper ASN.1 INTEGER.
     */
    public static ASN1Integer encode(byte[] bytes) {
        if (bytes.length <= 127) {
            byte[] encoded = new byte[bytes.length + 2];
            encoded[0] = tag;
            encoded[1] = (byte) bytes.length;
            System.arraycopy(bytes, 0, encoded, 2, bytes.length);
            return new ASN1Integer(encoded);
        } else {
            throw new UnsupportedOperationException("ToDo.");
        }
    }
}
