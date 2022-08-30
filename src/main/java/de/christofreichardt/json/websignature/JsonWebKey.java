package de.christofreichardt.json.websignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

public class JsonWebKey implements Traceable {

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

    final PublicKey publicKey;
    final PrivateKey privateKey;
    final String keyType;
    final String kid;
    final AlgorithmParameterSpec algorithmParameterSpec;
    final SecretKey secretKey;
    final String algorithm;

    public String getKeyType() {
        return this.keyType;
    }

    public String getKid() {
        return this.kid;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return this.algorithmParameterSpec;
    }

    public JsonWebKey(Builder builder) {
        this.publicKey = builder.publicKey;
        this.privateKey = builder.privateKey;
        if (this.publicKey instanceof ECPublicKey ecPublicKey) {
            this.algorithmParameterSpec = ecPublicKey.getParams();
        } else {
            this.algorithmParameterSpec = null;
        }
        if (Objects.nonNull(this.publicKey)) {
            this.keyType = this.publicKey.getAlgorithm();
        } else {
            this.keyType = "oct";
        }
        this.kid = builder.kid;
        this.secretKey = builder.secretKey;
        this.algorithm = Objects.nonNull(this.secretKey) ? JDK2JSON_ALGO_MAP.getOrDefault(this.secretKey.getAlgorithm(), "") : null;
    }

    static Builder of(PublicKey publicKey) {
        return new Builder(publicKey);
    }

    static Builder of(KeyPair keyPair) {
        return new Builder(keyPair);
    }

    static Builder of(SecretKey secretKey) {
        return new Builder(secretKey);
    }

    public static class Builder {
        final PublicKey publicKey;
        final PrivateKey privateKey;
        final SecretKey secretKey;
        String kid = null;

        public Builder(PublicKey publicKey) {
            this.publicKey = publicKey;
            this.privateKey = null;
            this.secretKey = null;
        }

        public Builder(KeyPair keyPair) {
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
            this.secretKey = null;
        }

        public Builder(SecretKey secretKey) {
            this.publicKey = null;
            this.privateKey = null;
            this.secretKey = secretKey;
        }

        public Builder withKid(String kid) {
            this.kid = kid;
            return this;
        }

        JsonWebKey build() {
            return new JsonWebKey(this);
        }
    }

    public JsonObject toJson() {
        AbstractTracer tracer = getCurrentTracer();
        tracer.entry("JsonObject", this, "toJson()");
        try {
            JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder()
                    .add("kty", this.keyType);
            if (this.kid != null) {
                jsonObjectBuilder.add("kid", this.kid);
            }
            if (this.algorithmParameterSpec instanceof ECParameterSpec ecParameterSpec) {
                jsonObjectBuilder.add("crv", ecParameterSpec.toString());
            }
            if (this.publicKey instanceof ECPublicKey ecPublicKey) {
                if (ecPublicKey.getW().getAffineX().signum() == -1 || ecPublicKey.getW().getAffineY().signum() == -1) {
                    throw new ArithmeticException();
                }
                int fieldSize = ecPublicKey.getParams().getCurve().getField().getFieldSize() / 8;
                byte[] xBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
                byte[] yBytes = JWSUtils.alignBytes(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
                jsonObjectBuilder
                        .add("x", JWSBase.encode(xBytes))
                        .add("y", JWSBase.encode(yBytes));

            }
            if (this.publicKey instanceof RSAPublicKey rsaPublicKey) {
                int keySize = rsaPublicKey.getModulus().bitLength();
                tracer.out().printfIndentln("keySize = %d", keySize);
                byte[] modulusBytes = JWSUtils.skipSurplusZeroes(rsaPublicKey.getModulus().toByteArray(), keySize / 8);
                tracer.out().printfIndentln("octets(rsaPublicKey) = %s", JWSUtils.formatBytes(modulusBytes));
                byte[] publicExponentBytes = JWSUtils.skipLeadingZeroes(rsaPublicKey.getPublicExponent().toByteArray());
                tracer.out().printfIndentln("octets(publicExponentBytes) = %s", JWSUtils.formatBytes(publicExponentBytes));
                jsonObjectBuilder
                        .add("n", JWSBase.encode(modulusBytes))
                        .add("e", JWSBase.encode(publicExponentBytes));
            }
            if (this.privateKey instanceof ECPrivateKey ecPrivateKey) {
                BigInteger order = ecPrivateKey.getParams().getOrder();
                byte[] dBytes = JWSUtils.alignBytes(ecPrivateKey.getS().toByteArray(), order.bitLength() / 8);
                jsonObjectBuilder.add("d", JWSBase.encode(dBytes));
            }
            if (this.privateKey instanceof RSAPrivateKey rsaPrivateKey) {
                byte[] privateExponentBytes = JWSUtils.skipLeadingZeroes(rsaPrivateKey.getPrivateExponent().toByteArray());
                tracer.out().printfIndentln("octets(privateExponentBytes) = %s", JWSUtils.formatBytes(privateExponentBytes));
                jsonObjectBuilder.add("d", JWSBase.encode(privateExponentBytes));
            }
            if (Objects.nonNull(this.secretKey)) {
                tracer.out().printfIndentln("octets(secretKey) = %s", JWSUtils.formatBytes(this.secretKey.getEncoded()));
                jsonObjectBuilder.add("k", JWSBase.encode(this.secretKey.getEncoded()));
                jsonObjectBuilder.add("alg", this.algorithm);
            }

            return jsonObjectBuilder.build();
        } finally {
            tracer.wayout();
        }
    }

    public static JsonWebKey fromJson(JsonObject jwkView) throws NoSuchAlgorithmException, InvalidKeySpecException {
        AbstractTracer tracer = TracerFactory.getInstance().getCurrentPoolTracer();
        tracer.entry("JsonWebKey", JsonWebKey.class, "fromJson(JsonObject jwkView)");

        try {
            if (!jwkView.containsKey("kty") || jwkView.get("kty").getValueType() != JsonValue.ValueType.STRING) {
                throw new IllegalArgumentException("Required 'kty' parameter missing or wrong type.");
            }
            String keyType = jwkView.getString("kty");
            tracer.out().printfIndentln("kty = %s", keyType);
            JsonWebKey jsonWebKey = switch (keyType) {
                case "EC" -> {
                    if (!jwkView.containsKey("crv") || jwkView.get("crv").getValueType() != JsonValue.ValueType.STRING) {
                        throw new IllegalArgumentException("Required 'crv' parameter missing or wrong type.");
                    }
                    String curve = jwkView.getString("crv");
                    if (!curve.startsWith("secp256r1")) {
                        throw new UnsupportedOperationException();
                    }
                    ECParameterSpec ecParameterSpec = EC_PARAMETER_SPEC_MAP.get("secp256r1");
                    if (!jwkView.containsKey("x") || jwkView.get("x").getValueType() != JsonValue.ValueType.STRING) {
                        throw new IllegalArgumentException("Required 'x' parameter missing or wrong type.");
                    }
                    if (!jwkView.containsKey("y") || jwkView.get("y").getValueType() != JsonValue.ValueType.STRING) {
                        throw new IllegalArgumentException("Required 'crv' parameter missing or wrong type.");
                    }
                    BigInteger x = new BigInteger(1, JWSBase.decodeToBytes(jwkView.getString("x")));
                    BigInteger y = new BigInteger(1, JWSBase.decodeToBytes(jwkView.getString("y")));
                    ECPoint w = new ECPoint(x, y);
                    ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
                    if (jwkView.containsKey("d") && jwkView.get("d").getValueType() == JsonValue.ValueType.STRING) {
                        BigInteger d = new BigInteger(1, JWSBase.decodeToBytes(jwkView.getString("d")));
                        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
                        PrivateKey privateKey = keyFactory.generatePrivate(ecPrivateKeySpec);
                        KeyPair keyPair = new KeyPair(publicKey, privateKey);
                        yield JsonWebKey.of(keyPair)
                                .withKid(jwkView.getString("kid", null))
                                .build();
                    }
                    yield JsonWebKey.of(publicKey)
                            .withKid(jwkView.getString("kid", null))
                            .build();
                }
                case "RSA" -> throw new UnsupportedOperationException();
                case "oct" -> throw new UnsupportedOperationException();
                default -> throw new UnsupportedOperationException();
            };

            return jsonWebKey;
        } finally {
            tracer.wayout();
        }
    }

    @Override
    public AbstractTracer getCurrentTracer() {
        return TracerFactory.getInstance().getCurrentPoolTracer();
    }
}
