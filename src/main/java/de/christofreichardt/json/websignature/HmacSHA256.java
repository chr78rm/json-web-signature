package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

/**
 *
 * @author Christof Reichardt
 */
public class HmacSHA256 implements JWSAlgorithm {

    final Mac mac;

    public HmacSHA256() throws NoSuchAlgorithmException {
        this.mac = Mac.getInstance("HmacSHA256");
    }

    @Override
    public void init(Key key) throws InvalidKeyException {
        this.mac.init(key);
    }

    @Override
    public void update(byte[] data) {
        this.mac.update(data);
    }

    @Override
    public byte[] signature() {
        return this.mac.doFinal();
    }

    @Override
    public boolean verify(byte[] signature) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String algorithm() {
        return this.mac.getAlgorithm();
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }

}
