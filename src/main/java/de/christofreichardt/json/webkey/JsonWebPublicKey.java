package de.christofreichardt.json.webkey;

final public class JsonWebPublicKey extends JsonWebKey {

    public JsonWebPublicKey(Builder builder) {
        super(builder.kid, "");
    }

    public static class Builder extends JsonWebKey.Builder {

        @Override
        JsonWebKey build() {
            return null;
        }
    }
}
