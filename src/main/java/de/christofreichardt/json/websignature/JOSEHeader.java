package de.christofreichardt.json.websignature;

import de.christofreichardt.json.webkey.JsonWebKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class JOSEHeader {

    final String alg;
    final String typ;
    final String kid;
    final JsonWebKey jsonWebKey;

    public JOSEHeader(Builder builder) {
        this.alg = builder.alg;
        this.typ = builder.typ;
        this.kid = builder.kid;
        this.jsonWebKey = builder.jsonWebKey;
    }

    public static Builder of (String alg) {
        return new Builder(alg);
    }

    public static class Builder {
        final String alg;
        String typ = null;
        String kid = null;
        JsonWebKey jsonWebKey = null;

        public Builder(String alg) {
            this.alg = alg;
        }

        public Builder withTyp(String typ) {
            this.typ = typ;
            return this;
        }

        public Builder withKid(String kid) {
            this.kid = kid;
            return this;
        }

        public Builder withJsonWebKey(JsonWebKey jsonWebKey) {
            this.jsonWebKey = jsonWebKey;
            return this;
        }

        public JOSEHeader build() {
            return new JOSEHeader(this);
        }
    }

    public JsonObject toJson() {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder()
                .add("alg", this.alg);
        if (this.typ != null) {
            jsonObjectBuilder.add("typ", this.typ);
        }
        if (this.kid != null) {
            jsonObjectBuilder.add("kid", this.kid);
        }
        if (this.jsonWebKey != null) {
            jsonObjectBuilder.add("jwk", this.jsonWebKey.toJson());
        }

        return jsonObjectBuilder.build();
    }
}
