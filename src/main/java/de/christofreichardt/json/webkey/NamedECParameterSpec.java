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

package de.christofreichardt.json.webkey;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Helper class needed to propagate the identifiers of this curve through serialization and deserialization.
 *
 * @author Christof Reichardt
 */
public class NamedECParameterSpec extends ECParameterSpec {

    private final String name;

    /**
     * Creates elliptic curve domain parameters based on the
     * specified values.
     *
     * @param name contains some identifiers for the curve, e.g. "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)"
     * @param curve the elliptic curve which this parameter
     *              defines.
     * @param g     the generator which is also known as the base point.
     * @param n     the order of the generator {@code g}.
     * @param h     the cofactor.
     * @throws NullPointerException     if {@code curve},
     *                                            {@code g}, or {@code n} is null.
     * @throws IllegalArgumentException if {@code n}
     *                                            or {@code h} is not positive.
     */
    public NamedECParameterSpec(String name, EllipticCurve curve, ECPoint g, BigInteger n, int h) {
        super(curve, g, n, h);
        this.name = name;
    }

    /**
     * Returns some identifier of the wrapped curve, e.g. "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)"
     *
     * @return the identifiers of the wrapped curve.
     */
    @Override
    public String toString() {
        return this.name;
    }
}
