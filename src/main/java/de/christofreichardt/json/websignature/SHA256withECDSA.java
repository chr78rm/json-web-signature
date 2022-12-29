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
import java.math.BigInteger;

import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
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
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getDefaultTracer();
    }
}
