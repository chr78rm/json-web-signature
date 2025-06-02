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

package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

/**
 * An apapter to the underlying MAC instance provided by the Java platform which has the same name.
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/19/docs/api/java.base/javax/crypto/Mac.html">MAC</a>
 * @author Christof Reichardt
 */
public class HmacSHA256 implements JWSAlgorithm {

    final Mac mac;

    HmacSHA256() throws NoSuchAlgorithmException {
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
        return MessageDigest.isEqual(this.mac.doFinal(), signature);
    }

    @Override
    public String algorithm() {
        return this.mac.getAlgorithm();
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
