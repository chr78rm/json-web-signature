package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

public class SHA256withECDSA implements JWSAlgorithm {

    final Signature signature;

    public SHA256withECDSA() throws NoSuchAlgorithmException {
        this.signature = Signature.getInstance("SHA256withECDSA");
    }

    @Override
    public void init(Key key) throws GeneralSecurityException {
        if (key instanceof ECPrivateKey privateKey) {
            this.signature.initSign(privateKey);
        } else if (key instanceof ECPublicKey publicKey) {
            this.signature.initVerify(publicKey);
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
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
