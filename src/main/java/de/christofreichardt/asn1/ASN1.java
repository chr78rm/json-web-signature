package de.christofreichardt.asn1;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Arrays;

public sealed abstract class ASN1 implements Traceable permits ASN1Integer, ASN1IntSequence {
    static public final int LENGTH_FORM_DISCRIMINATOR = 0x80, LENGTH_OCTETS_MASK = 0x7f;
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
            if ((this.bytes[1] & LENGTH_FORM_DISCRIMINATOR) == 0) { // short form
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
                int lengthOctets = this.bytes[1] & LENGTH_OCTETS_MASK;
                tracer.out().printfIndentln("lengthOctets = %d", lengthOctets);
                if (lengthOctets == 0) {
                    throw new IllegalArgumentException("Number of length octets must not be zero.");
                } else if (lengthOctets > 1) {
                    throw new UnsupportedOperationException("ToDo.");
                }
                detectedLength = this.bytes[2] & 0xff;
                tracer.out().printfIndentln("detectedLength = %d", detectedLength);
                int actualLength = this.bytes.length - 3;
                if (detectedLength > actualLength) {
                    throw new IllegalArgumentException("Too few bytes (=%d) for detected detectedLength (=%d).".formatted(actualLength, detectedLength));
                }
                startIndex = 3;
            }

            return new Length(this.bytes.length, detectedLength, startIndex);
        } finally {
            tracer.wayout();
        }
    }

    public byte[] encoded() {
        return Arrays.copyOfRange(this.bytes, 0, this.asn1Length.detectedLength() + this.asn1Length.startIndex());
    }

    public byte[] actualBytes() {
        return Arrays.copyOfRange(this.bytes, this.asn1Length.startIndex(), this.asn1Length.startIndex() + this.asn1Length.detectedLength());
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
