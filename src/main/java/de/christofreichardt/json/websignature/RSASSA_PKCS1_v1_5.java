package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author Christof Reichardt
 */
public class RSASSA_PKCS1_v1_5 implements JWSAlgorithm {
    
    final Signature signature;

    public RSASSA_PKCS1_v1_5() throws NoSuchAlgorithmException {
        this.signature = Signature.getInstance("SHA256withRSA");
    }

    @Override
    public void init(Key key) throws GeneralSecurityException {
        if (key instanceof RSAPrivateKey privateKey) {
            this.signature.initSign(privateKey);
        } else if (key instanceof RSAPublicKey publicKey) {
            this.signature.initVerify(publicKey);
        } else {
            throw new InvalidKeyException();
        }
    }

    @Override
    public void update(byte[] data) throws SignatureException {
        this.signature.update(data);
    }

    @Override
    public byte[] signature() throws SignatureException {
        return this.signature.sign();
    }

    @Override
    public boolean verify(byte[] signature) throws SignatureException {
        return this.signature.verify(signature);
    }

    @Override
    public String algorithm() {
        return this.signature.getAlgorithm();
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
    
}
