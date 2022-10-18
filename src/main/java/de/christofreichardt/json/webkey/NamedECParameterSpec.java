package de.christofreichardt.json.webkey;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class NamedECParameterSpec extends ECParameterSpec {

    private String name;

    /**
     * Creates elliptic curve domain parameters based on the
     * specified values.
     *
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

    @Override
    public String toString() {
        return this.name;
    }
}
