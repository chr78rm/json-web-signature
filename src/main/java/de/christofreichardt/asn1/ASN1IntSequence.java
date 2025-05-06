package de.christofreichardt.asn1;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

public final class ASN1IntSequence extends ASN1 {
    static public final int tag = 0x30;

    public ASN1IntSequence(byte[] bytes) {
        super(bytes);
        if (super.bytes[0] != tag) {
            throw new IllegalArgumentException("Wrong tag: 0x%02x. ASN.1 SEQUENCE expected.".formatted(bytes[0]));
        }
    }

    public class Iterator implements java.util.Iterator<ASN1Integer>, Traceable {
        int remaining = ASN1IntSequence.this.asn1Length.rawLength() - ASN1IntSequence.this.asn1Length.startIndex();
        int index = ASN1IntSequence.this.asn1Length.startIndex();

        @Override
        public boolean hasNext() {
            return this.remaining > 0;
        }

        @Override
        public ASN1Integer next() {
            AbstractTracer tracer = getCurrentTracer();
            tracer.entry("ASN1Integer", this, "next()");

            try {
                if (this.remaining <= 0) {
                    throw new NoSuchElementException();
                }
                ASN1Integer asn1Integer = new ASN1Integer(ASN1IntSequence.this.bytes, this.index);
                int consumed = asn1Integer.asn1Length.startIndex() + asn1Integer.asn1Length.detectedLength();
                this.remaining = this.remaining - consumed;
                this.index = this.index + consumed;
                return asn1Integer;
            } finally {
                tracer.wayout();
            }
        }

        @Override
        public AbstractTracer getCurrentTracer() {
            return ASN1IntSequence.this.getCurrentTracer();
        }
    }

    public Iterator iterator() {
        return new Iterator();
    }

    static ASN1IntSequence fromASN1Integers(ASN1Integer... asn1Integers) {
        int length = Stream.of(asn1Integers)
                .mapToInt(value -> value.asn1Length.rawLength())
                .sum();
        int startIndex;
        if (length <= ASN1.SHORT_LENGTH) {
            byte[] encoded = new byte[length + 2];
            encoded[0] = tag;
            encoded[1] = (byte) length;
            startIndex = 2;
            for (ASN1Integer asn1Integer : asn1Integers) {
                System.arraycopy(asn1Integer.encoded(), 0, encoded, startIndex, asn1Integer.asn1Length.rawLength());
                startIndex += asn1Integer.asn1Length.rawLength();
            }
            return new ASN1IntSequence(encoded);
        } else {
            throw new UnsupportedOperationException("ToDo.");
        }
    }

    @Override
    public String toString() {
        return HexFormat.ofDelimiter(" ").withPrefix("0x").formatHex(encoded());
    }
}
