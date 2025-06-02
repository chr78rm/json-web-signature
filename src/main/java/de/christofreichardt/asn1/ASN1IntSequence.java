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
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

/**
 * ASN.1 helper class representing a ASN.1 {@code SEQUENCE} of {@code INTEGER}s.
 *
 * @author Christof Reichardt
 */
public final class ASN1IntSequence extends ASN1 {
    static final int tag = 0x30;

    /**
     * Creates an ASN.1 {@code SEQUENCE} of {@code INTEGER}s
     *
     * @param bytes the DER encoded bytes representing an ASN.1 {@code SEQUENCE} of {@code INTEGER}s.
     */
    public ASN1IntSequence(byte[] bytes) {
        super(bytes);
        if (super.bytes[0] != tag) {
            throw new IllegalArgumentException("Wrong tag: 0x%02x. ASN.1 SEQUENCE expected.".formatted(bytes[0]));
        }
    }

    /**
     * {@code Iterator} over ASN.1 {@code INTEGER}s.
     */
    public class Iterator implements java.util.Iterator<ASN1Integer>, Traceable {
        int remaining = ASN1IntSequence.this.asn1Length.rawLength() - ASN1IntSequence.this.asn1Length.startIndex();
        int index = ASN1IntSequence.this.asn1Length.startIndex();

        /**
         * Creates an {@code Iterator} over ASN.1 {@code INTEGER}s.
         */
        public Iterator() {
        }

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

    /**
     * Returns an {@link de.christofreichardt.asn1.ASN1IntSequence.Iterator}.
     *
     * @return an {@link de.christofreichardt.asn1.ASN1IntSequence.Iterator} over the INTEGERs in this SEQUENCE
     */
    public Iterator iterator() {
        return new Iterator();
    }

    /**
     * Creates an ASN.1 {@code SEQUENCE} of the given {@link de.christofreichardt.asn1.ASN1Integer}s.
     *
     * @param asn1Integers some {@link de.christofreichardt.asn1.ASN1Integer}s for the {@code SEQUENCE}.
     * @return an ASN.1 {@code SEQUENCE} comprising the given {@link de.christofreichardt.asn1.ASN1Integer}s.
     */
    public static ASN1IntSequence fromASN1Integers(ASN1Integer... asn1Integers) {
        int length = Stream.of(asn1Integers)
                .mapToInt(value -> value.asn1Length.rawLength())
                .sum();
        int startIndex;
        byte[] encoded;
        if (length <= ASN1.SHORT_LENGTH) {
            encoded = new byte[length + 2];
            encoded[0] = tag;
            encoded[1] = (byte) length;
            startIndex = 2;
        } else if (length <= 255) {
            encoded = new byte[length + 3];
            encoded[0] = tag;
            encoded[1] = (byte) 0x81;
            encoded[2] = (byte) length;
            startIndex = 3;
        } else {
            throw new UnsupportedOperationException("ToDo.");
        }
        for (ASN1Integer asn1Integer : asn1Integers) {
            System.arraycopy(asn1Integer.encoded(), 0, encoded, startIndex, asn1Integer.asn1Length.rawLength());
            startIndex += asn1Integer.asn1Length.rawLength();
        }

        return new ASN1IntSequence(encoded);
    }

    @Override
    public String toString() {
        return HexFormat.ofDelimiter(" ").withPrefix("0x").formatHex(encoded());
    }
}
