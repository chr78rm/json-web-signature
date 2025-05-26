package de.christofreichardt.json.websignature;

import de.christofreichardt.asn1.ASN1IntSequence;
import de.christofreichardt.asn1.ASN1Integer;
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

/**
 * An apapter to the underlying Signature instance provided by the Java platform which has the same name.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/Signature.html">Signature</a>
 * @author Christof Reichardt
 */
public class SHA512WithECDSA implements JWSAlgorithm {

    final Signature signature;

    SHA512WithECDSA() throws NoSuchAlgorithmException {
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
            tracer.out().printfIndentln("signature.length = %d, signature = %s", signature.length, HexFormat.ofDelimiter(" ").formatHex(signature));

            ASN1IntSequence asn1IntSequence = new ASN1IntSequence(signature);
            ASN1IntSequence.Iterator iter = asn1IntSequence.iterator();
            ASN1Integer asn1_r = iter.next();
            if (!asn1_r.isShortForm()) {
                throw new IllegalArgumentException("Short form of length octets required.");
            }
            ASN1Integer asn1_s = iter.next();
            if (!asn1_s.isShortForm()) {
                throw new IllegalArgumentException("Short form of length octets required.");
            }
            if (iter.hasNext()) {
                throw new IllegalArgumentException("Only two integers expected.");
            }
            byte[] r = JsonWebKeyUtils.alignBytes(asn1_r.actualBytes(), 66);
            byte[] s = JsonWebKeyUtils.alignBytes(asn1_s.actualBytes(), 66);
            signature = new byte[132];
            System.arraycopy(r, 0, signature, 0, 66);
            System.arraycopy(s, 0, signature, 66, 66);

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

            ASN1Integer asn1_r = ASN1Integer.encode(r);
            ASN1Integer asn1_s = ASN1Integer.encode(s);
            ASN1IntSequence asn1Signature = ASN1IntSequence.fromASN1Integers(asn1_r, asn1_s);

            return asn1Signature.encoded();
        } finally {
            tracer.wayout();
        }
   }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
