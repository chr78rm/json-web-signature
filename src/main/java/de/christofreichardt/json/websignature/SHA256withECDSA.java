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

package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.webkey.JsonWebKeyUtils;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.util.HexFormat;
import java.util.Objects;

/**
 * An apapter to the underlying Signature instance provided by the Java platform which has the same name.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/security/Signature.html">Signature</a>
 * @author Christof Reichardt
 */
public class SHA256withECDSA implements JWSAlgorithm {

    final Signature signature;

    SHA256withECDSA() throws NoSuchAlgorithmException {
        this.signature = Signature.getInstance("SHA256withECDSA");
    }

    @Override
    public void init(Key key) throws GeneralSecurityException {
        validateCurveParameter(key);
        if (key instanceof ECPrivateKey privateKey) {
            this.signature.initSign(privateKey);
        } else if (key instanceof ECPublicKey publicKey) {
            this.signature.initVerify(publicKey);
        }
    }

    void validateCurveParameter(Key key) throws InvalidKeyException {
        if (key instanceof ECKey ecKey) {
            if (ecKey.getParams().getCurve().getField() instanceof ECFieldFp ecFieldFp) {
                BigInteger prime = ecFieldFp.getP();
                if (!Objects.equals(prime, new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"))) {
                    throw new InvalidKeyException();
                }
                if (!Objects.equals(ecKey.getParams().getOrder(), new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"))) {
                    throw new InvalidKeyException();
                }
                if (!Objects.equals(new BigInteger("-3"), ecKey.getParams().getCurve().getA().subtract(prime))) {
                    throw new InvalidKeyException();
                }
                if (!Objects.equals(ecKey.getParams().getCurve().getB().toString(16), "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")) {
                    throw new InvalidKeyException();
                }
                if (!Objects.equals(ecKey.getParams().getGenerator().getAffineX().toString(16).toLowerCase(), "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")) {
                    throw new InvalidKeyException();
                }
                if (!Objects.equals(ecKey.getParams().getGenerator().getAffineY().toString(16).toLowerCase(), "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")) {
                    throw new InvalidKeyException();
                }
            } else {
                throw new InvalidKeyException();
            }
        } else {
            throw new InvalidKeyException();
        }
    }

    @Override
    public void update(byte[] data) throws GeneralSecurityException {
        this.signature.update(data);
    }

    @Override
    public byte[] signature() throws GeneralSecurityException {
        return this.signature.sign();
    }

    @Override
    public boolean verify(byte[] signature) throws GeneralSecurityException {
        return this.signature.verify(signature);
    }

    @Override
    public String algorithm() {
        return this.signature.getAlgorithm();
    }

    @Override
    public String postSigning(byte[] signature) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("String", this, "postSigning(byte[] signature)");

        try {
            int mask = 0x80;
            HexFormat hexFormat = HexFormat.ofDelimiter(" ");
            tracer.out().printfIndentln("signature.length = %d, signature = %s", signature.length, hexFormat.formatHex(signature));
            tracer.out().printfIndentln("mask = %s, signature[1] = %s, mask AND signature[1] = %s",
                    hexFormat.toHexDigits(mask), hexFormat.toHexDigits((int) signature[1]), hexFormat.toHexDigits(mask & signature[1]));

            byte type = signature[0]; // should be 0x30 meaning SEQUENCE
            byte lengthOfSequence = signature[1];
            byte dataType1 = signature[2]; // should be 0x02 meaning INTEGER
            byte lengthOfInteger1 = signature[3];
            byte dataType2 = signature[3 + lengthOfInteger1 + 1]; // should be 0x02 meaning INTEGER
            byte lengthOfInteger2 = signature[3 + lengthOfInteger1 + 2];
            tracer.out().printfIndentln("type = 0x%02x, lengthOfSequence = %d, dataType1 = 0x%02x, lengthOfInteger1 = %d, dataType2 = 0x%02x, lengthOfInteger2 = %d",
                    type, lengthOfSequence, dataType1, lengthOfInteger1, dataType2, lengthOfInteger2);

            if (type != 0x30) {
                throw new IllegalArgumentException("ASN.1 SEQUENCE expected.");
            }
            if ((mask & (int) lengthOfSequence) != 0) {
                throw new IllegalArgumentException("Short form of length octets required.");
            }
            if (lengthOfSequence != signature.length - 2) {
                throw new IllegalArgumentException("Denoted length of the ASN.1 SEQUENCE doesn't match.");
            }
            if (dataType1 != 0x02) {
                throw new IllegalArgumentException("ASN.1 INTEGER expected.");
            }
            if ((mask & (int) lengthOfInteger1) != 0) {
                throw new IllegalArgumentException("Short form of length octets required.");
            }
            if (dataType2 != 0x02) {
                throw new IllegalArgumentException("ASN.1 INTEGER expected.");
            }
            if ((mask & (int) lengthOfInteger2) != 0) {
                throw new IllegalArgumentException("Short form of length octets required.");
            }

            byte[] r = new byte[lengthOfInteger1];
            System.arraycopy(signature, 4, r, 0, lengthOfInteger1);
            tracer.out().printfIndentln("r = %s", hexFormat.formatHex(r));
            r = JsonWebKeyUtils.alignBytes(r, 32);
            tracer.out().printfIndentln("aligned(r) = %s", hexFormat.formatHex(r));

            byte[] s = new byte[lengthOfInteger2];
            System.arraycopy(signature, 3 + lengthOfInteger1 + 3, s, 0, lengthOfInteger2);
            tracer.out().printfIndentln("s = %s", hexFormat.formatHex(s));
            s = JsonWebKeyUtils.alignBytes(s, 32);
            tracer.out().printfIndentln("aligned(s) = %s", hexFormat.formatHex(s));

            signature = new byte[64];
            System.arraycopy(r, 0, signature, 0, 32);
            System.arraycopy(s, 0, signature, 32, 32);

            return JWSBase.encode(signature);
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public byte[] preValidating(byte[] signature) {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("byte[]", this, "preValidating(byte[] signature)");

        try {
            HexFormat hexFormat = HexFormat.ofDelimiter(" ");
            tracer.out().printfIndentln("signature.length = %d, signature = %s", signature.length, hexFormat.formatHex(signature));

            if (signature.length != 64) {
                throw new IllegalArgumentException("Expected exactly 64 octets.");
            }

            byte[] r = new byte[32];
            System.arraycopy(signature, 0, r, 0, 32);
            r = JsonWebKeyUtils.skipLeadingZeroes(r);

            byte[] s = new byte[32];
            System.arraycopy(signature, 32, s, 0, 32);
            s = JsonWebKeyUtils.skipLeadingZeroes(s);

            byte[] asn1Encoding = new byte[r.length + s.length + 6]; // 6 ASN.1 tags
            asn1Encoding[0] = 0x30; // tag for SEQUENCE
            asn1Encoding[1] = (byte) (r.length + s.length + 4); // denotes length of SEQUENCE
            asn1Encoding[2] = 0x02; // tag for INTEGER
            asn1Encoding[3] = (byte) r.length; // denotes length of INTEGER
            asn1Encoding[3 + r.length + 1] = 0x02; // tag for INTEGER
            asn1Encoding[3 + r.length + 2] = (byte) s.length; // denotes length of INTEGER
            System.arraycopy(r, 0, asn1Encoding, 4, r.length);
            System.arraycopy(s, 0, asn1Encoding, 3 + r.length + 3, s.length);

            tracer.out().printfIndentln("asn1Encoding = %s", hexFormat.formatHex(asn1Encoding));

            return asn1Encoding;
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
