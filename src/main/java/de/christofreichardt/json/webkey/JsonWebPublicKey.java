package de.christofreichardt.json.webkey;

final public class JsonWebPublicKey extends JsonWebKey {

    public JsonWebPublicKey(Builder builder) {
        super(builder.kid, "");
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        @Override
        JsonWebPublicKey build() {
            return null;
        }
    }
}
