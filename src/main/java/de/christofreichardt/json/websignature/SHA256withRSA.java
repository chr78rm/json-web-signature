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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * An apapter to the underlying Signature instance provided by the Java platform which has the same name.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/security/Signature.html">Signature</a>
 * @author Christof Reichardt
 */
public class SHA256withRSA implements JWSAlgorithm {
    
    final Signature signature;

    SHA256withRSA() throws NoSuchAlgorithmException {
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
    public String postSigning(byte[] signature) {
        return JWSBase.encode(signature);
    }

    @Override
    public byte[] preValidating(byte[] signature) {
        return signature;
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
    
}
