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

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Arrays;

/**
 * Abstract base class for the ASN.1 helper classes.
 *
 * @author Christof Reichardt
 */
public sealed abstract class ASN1 implements Traceable permits ASN1Integer, ASN1IntSequence {
    static final int LENGTH_FORM_DISCRIMINATOR = 0x80, LENGTH_OCTETS_MASK = 0x7f;
    static final int SHORT_LENGTH = 127;
    final byte[] bytes;
    final ASN1.Length asn1Length;

    ASN1(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
        this.asn1Length = length();
    }

    /**
     * Indicates if the underlying ASN.1 object is in short form (&lt;= 127 octets).
     *
     * @return true if in short form.
     */
    public boolean isShortForm() {
        return this.asn1Length.detectedLength <= SHORT_LENGTH;
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

    /**
     * Returns a copy of the bytes representing the encoded ASN.1 object.
     *
     * @return the encoded bytes. A new array will be allocated each time the method is called.
     */
    public byte[] encoded() {
        return Arrays.copyOfRange(this.bytes, 0, this.asn1Length.detectedLength() + this.asn1Length.startIndex());
    }

    /**
     * Returns a copy of the bytes representing the actual ASN.1 object without identifier and length octets.
     *
     * @return the content octets. A new array will be allocated each time the method is called.
     */
    public byte[] actualBytes() {
        return Arrays.copyOfRange(this.bytes, this.asn1Length.startIndex(), this.asn1Length.startIndex() + this.asn1Length.detectedLength());
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
