package de.christofreichardt.asn1;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Arrays;

public sealed abstract class ASN1 implements Traceable permits ASN1Integer, ASN1IntSequence {
    static public final int mask = 0x80;
    static public final int SHORT_LENGTH = 127;
    final byte[] bytes;
    final ASN1.Length asn1Length;

    public ASN1(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
        this.asn1Length = length();
    }

    record Length(int rawLength, int detectedLength, int startIndex) {}

    Length length() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("int", this, "length()");

        try {
            int detectedLength, startIndex;
            if ((this.bytes[1] & mask) == 0) { // short form
                tracer.out().printfIndentln("Short form detected ...");
                detectedLength = this.bytes[1];
                tracer.out().printfIndentln("detectedLength = %d", detectedLength);
                int actualLength = this.bytes.length - 2;
                if (detectedLength > actualLength) {
                    throw new IllegalArgumentException("Too few bytes (=%d) for detected detectedLength (=%d).".formatted(actualLength, detectedLength));
                }
                startIndex = 2;
            } else { // long form
                tracer.out().printfIndentln("Long form detected ...");
                throw new UnsupportedOperationException("ToDo.");
            }

            return new Length(this.bytes.length, detectedLength, startIndex);
        } finally {
            tracer.wayout();
        }
    }

    byte[] encoded() {
        return Arrays.copyOfRange(this.bytes, 0, this.asn1Length.detectedLength() + this.asn1Length.startIndex());
    }

    byte[] actualBytes() {
        return Arrays.copyOfRange(this.bytes, this.asn1Length.startIndex(), this.asn1Length.startIndex() + this.asn1Length.detectedLength());
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
