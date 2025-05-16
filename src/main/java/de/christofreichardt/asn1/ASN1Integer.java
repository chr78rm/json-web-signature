package de.christofreichardt.asn1;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Arrays;
import java.util.HexFormat;

public final class ASN1Integer extends ASN1 {
    static public final int tag = 0x02;

    public ASN1Integer(byte[] bytes) {
        super(bytes);
        if (super.bytes[0] != tag) {
            throw new IllegalArgumentException("Wrong tag: 0x%02x. ASN.1 INTEGER expected.".formatted(bytes[0]));
        }
    }

    public ASN1Integer(byte[] bytes, int from) {
        this(Arrays.copyOfRange(bytes, from, bytes.length));
    }

    @Override
    public String toString() {
        return HexFormat.ofDelimiter(" ").withPrefix("0x").formatHex(encoded());
    }

    public static ASN1Integer fromBytes(byte[] bytes) {
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
