package de.christofreichardt.json.webkey;

final public class JsonWebSecretKey extends JsonWebKey {

    public JsonWebSecretKey(Builder builder) {
        super("", "oct");
    }

    public static class Builder extends JsonWebKey.Builder<Builder> {

        @Override
        JsonWebSecretKey build() {
            return null;
        }
    }
}
