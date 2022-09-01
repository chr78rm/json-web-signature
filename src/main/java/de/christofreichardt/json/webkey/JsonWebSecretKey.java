package de.christofreichardt.json.webkey;

final public class JsonWebSecretKey extends JsonWebKey {

    public JsonWebSecretKey(Builder builder) {
        super("", "oct");
    }

    public static class Builder extends JsonWebKey.Builder {

        @Override
        JsonWebKey build() {
            return null;
        }
    }
}
