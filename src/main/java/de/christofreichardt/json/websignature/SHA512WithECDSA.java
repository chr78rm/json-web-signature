package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.json.webkey.JsonWebKey;
import de.christofreichardt.json.webkey.JsonWebKeyUtils;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.util.HexFormat;
import java.util.Objects;

public class SHA512WithECDSA implements JWSAlgorithm {

    final Signature signature;

    public SHA512WithECDSA() throws NoSuchAlgorithmException {
        this.signature = Signature.getInstance("SHA512withECDSA");
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
        if (!(key instanceof ECKey ecKey)) {
            throw new InvalidKeyException();
        }

        ECParameterSpec ecParameterSpec = JsonWebKey.EC_PARAMETER_SPEC_MAP.get("secp521r1");
        BigInteger prime;
        if (!(ecParameterSpec.getCurve().getField() instanceof ECFieldFp ecFieldFp1)) {
            throw new AssertionError();
        }
        prime = ecFieldFp1.getP();

        if (!(ecKey.getParams().getCurve().getField() instanceof ECFieldFp ecFieldFp2)) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecFieldFp2.getP(), prime)) {
            throw new InvalidKeyException();
        }
        if (ecFieldFp2.getFieldSize() != 521) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecKey.getParams().getCurve().getA(), ecParameterSpec.getCurve().getA())) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecKey.getParams().getCurve().getB(), ecParameterSpec.getCurve().getB())) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecKey.getParams().getGenerator().getAffineX(), ecParameterSpec.getGenerator().getAffineX())) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecKey.getParams().getGenerator().getAffineY(), ecParameterSpec.getGenerator().getAffineY())) {
            throw new InvalidKeyException();
        }
        if (!Objects.equals(ecKey.getParams().getOrder(), ecParameterSpec.getOrder())) {
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
            int mask1 = 0x80, mask2 = 0x7f, mask3 = 0xff;
            HexFormat hexFormat = HexFormat.ofDelimiter(" ");
            tracer.out().printfIndentln("signature.length = %d, signature = %s", signature.length, hexFormat.formatHex(signature));
            tracer.out().printfIndentln("mask1 = %s, signature[1] = %s, mask1 AND signature[1] = %s",
                    hexFormat.toHexDigits(mask1), hexFormat.toHexDigits((int) signature[1]), hexFormat.toHexDigits(mask1 & signature[1]));

            byte type = signature[0]; // should be 0x30 meaning SEQUENCE
            if (type != 0x30) {
                throw new IllegalArgumentException("ASN.1 SEQUENCE expected.");
            }
            if ((mask1 & (int) signature[1]) == mask1) {
                int lenOctets = mask2 & signature[1];
                tracer.out().printfIndentln("lenOctets = %d", lenOctets);
                if (lenOctets != 1) {
                    throw new IllegalArgumentException("Expected exactly one additional length octet at this time.");
                }
                int lenOfSequence = signature[2] & mask3;
                tracer.out().printfIndentln("hex(lenOfSequence) = %s, lenOfSequence = %d", hexFormat.toHexDigits(lenOfSequence), lenOfSequence);
                if (signature.length - 3 != lenOfSequence) {
                    throw new IllegalArgumentException("Denoted length of the ASN.1 SEQUENCE doesn't match.");
                }
                byte dataType1 = signature[3];
                if (dataType1 != 0x02) {
                    throw new IllegalArgumentException("ASN.1 INTEGER expected.");
                }
                int lenInteger1 = signature[4] & mask3;
                tracer.out().printfIndentln("lenInteger1 = %d", lenInteger1);
                byte dataType2 = signature[5 + lenInteger1];
                if (dataType2 != 0x02) {
                    throw new IllegalArgumentException("ASN.1 INTEGER expected.");
                }
                int lenInteger2 = signature[5 + lenInteger1 + 1] & mask3;
                tracer.out().printfIndentln("lenInteger2 = %d", lenInteger2);

                byte[] r = new byte[lenInteger1];
                System.arraycopy(signature, 5, r, 0, lenInteger1);
                tracer.out().printfIndentln("r = %s", hexFormat.formatHex(r));
                r = JsonWebKeyUtils.alignBytes(r, 66);
                tracer.out().printfIndentln("aligned(r) = %s", hexFormat.formatHex(r));

                byte[] s = new byte[lenInteger2];
                System.arraycopy(signature, 5 + lenInteger1 + 2, s, 0, lenInteger2);
                tracer.out().printfIndentln("s = %s", hexFormat.formatHex(s));
                s = JsonWebKeyUtils.alignBytes(s, 66);
                tracer.out().printfIndentln("aligned(s) = %s", hexFormat.formatHex(s));

                signature = new byte[132];
                System.arraycopy(r, 0, signature, 0, 66);
                System.arraycopy(s, 0, signature, 66, 66);
            } else {
                throw new UnsupportedOperationException("To do.");
            }

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

            if (signature.length != 132) {
                throw new IllegalArgumentException("Expected exactly 132 octets.");
            }

            byte[] r = new byte[66];
            System.arraycopy(signature, 0, r, 0, 66);
            r = JsonWebKeyUtils.skipLeadingZeroes(r);

            byte[] s = new byte[66];
            System.arraycopy(signature, 66, s, 0, 66);
            s = JsonWebKeyUtils.skipLeadingZeroes(s);

            tracer.out().printfIndentln("len(r) = %d, len(s) = %d, len(r) + len(s) + 4 = %d", r.length, s.length, r.length + s.length + 4);
            if (r.length + s.length + 4 > 127) {
                byte[] asn1Encoding = new byte[r.length + s.length + 7]; // 7 ASN.1 tags because we need the long form for the length of the sequence
                asn1Encoding[0] = 0x30; // tag for SEQUENCE
                asn1Encoding[1] = (byte) (0x80 + 0x01); // Bit 8 has value 1 denoting the long form and bits 7-1 give the number of additional octets (we need only one)
                tracer.out().printfIndentln("asn1Encoding[1] = %s", hexFormat.toHexDigits(asn1Encoding[1]));
                asn1Encoding[2] = (byte) (r.length + s.length + 4); // the length of the following sequence
                tracer.out().printfIndentln("asn1Encoding[2] = %s", hexFormat.toHexDigits(asn1Encoding[2]));
                asn1Encoding[3] = 0x02; // tag for INTEGER
                asn1Encoding[4] = (byte) r.length; // denotes length of r
                asn1Encoding[5 + r.length] = 0x02; // tag for INTEGER
                asn1Encoding[5 + r.length + 1] = (byte) s.length; // denotes length of s
                System.arraycopy(r, 0, asn1Encoding, 5, r.length);
                System.arraycopy(s, 0, asn1Encoding, 5 + r.length + 2, s.length);

                tracer.out().printfIndentln("asn1Encoding = %s", hexFormat.formatHex(asn1Encoding));

                return asn1Encoding;
            } else {
                throw new UnsupportedOperationException("To do.");
            }
        } finally {
            tracer.wayout();
        }
   }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
