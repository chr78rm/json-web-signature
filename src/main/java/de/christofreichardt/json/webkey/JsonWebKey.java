package de.christofreichardt.json.webkey;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

abstract public sealed class JsonWebKey permits JsonWebKeyPair, JsonWebPublicKey, JsonWebSecretKey {

    final static public Map<String, String> JDK2JSON_ALGO_MAP = Map.of("HmacSHA256", "HS256");
    final static public Map<String, ECParameterSpec> EC_PARAMETER_SPEC_MAP = new HashMap<>();

    static {
        BigInteger p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
        ECFieldFp ecFieldFp = new ECFieldFp(p);
        BigInteger a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
        BigInteger b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
        EllipticCurve secp256r1 = new EllipticCurve(ecFieldFp, a, b);
        ECPoint generator = new ECPoint(
                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
        );
        BigInteger order = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(secp256r1, generator, order, 1);
        EC_PARAMETER_SPEC_MAP.put("secp256r1", ecParameterSpec);
    }

    abstract public static class Builder<T extends Builder<T>> {
        String kid = UUID.randomUUID().toString();

        public T withKid(String kid) {
            this.kid = kid;
            return (T) this;
        }

        abstract JsonWebKey build() throws GeneralSecurityException;
    }


    final String kid;
    final String keyType;

    public JsonWebKey(String kid, String keyType) {
        this.kid = kid;
        this.keyType = keyType;
    }

    @Override
    public String toString() {
        return String.format("JsonWebKey[class=%s, kid=%s]", this.getClass().getSimpleName(), this.kid);
    }
}
