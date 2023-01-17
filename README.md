# Abstract

This library implements a subset of the RFCs [7515](https://www.rfc-editor.org/rfc/rfc7515.html) (JSON Web Signature), [7517](https://www.rfc-editor.org/rfc/rfc7517) (JSON Web Key) 
and [7518](https://www.rfc-editor.org/rfc/rfc7518.html) (JSON Web Algorithms). It uses and works together with [Jakarta JSON Processing](https://github.com/jakartaee/jsonp-api). An appropriate
implementation of the Jakarta JSON Processing API must be provided at runtime, e.g. [Eclipse Parsson](https://github.com/eclipse-ee4j/parsson).

# Build

[Maven](https://maven.apache.org/) is required to build the project. First clone the project: `git clone https://github.com/chr78rm/json-web-signature.git` and then you can install the
library with `mvn clean install` into the local Maven repo.

# Usage

## Required Dependencies

You will need the actual library on the classpath, of course, and an implementation of the Jakarta JSON Processing API at runtime, e.g.:
```
    <dependency>
      <groupId>de.christofreichardt</groupId>
      <artifactId>json-web-signature</artifactId>
      <version>1.0.0-beta</version>
    </dependency>
    <dependency>
      <groupId>org.eclipse.parsson</groupId>
      <artifactId>jakarta.json</artifactId>
      <version>1.1.1</version>
      <scope>runtime</scope>
    </dependency>
```

## JSON Web Algorithms

At present, the library supports the algorithms which are required or rather recommended by the specification: HS256 (HMAC using SHA-256), RS256 (RSASSA-PKCS1-v1_5 using SHA-256) 
and ES256 (ECDSA using P-256 and SHA-256).

## JSON Web Key

The subsequent example shows how to create a JSON Web Key suitable for use with ECDSA (curve P-256 and SHA-256):
```
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
    keyPairGenerator.initialize(ecGenParameterSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    JsonWebKeyPair jsonWebKeyPair = JsonWebKeyPair.of(keyPair)
            .withKid("45dc44ba-531b-4039-8980-c28c0ac6e690")
            .build();
```
The JSON representation of the above key pair is as follows:
```
    {
        "kty": "EC",
        "kid": "45dc44ba-531b-4039-8980-c28c0ac6e690",
        "crv": "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)",
        "x": "_NpBXbIUH-OcV4XirIcKBaXafX895eKTyekhLo9VDYA",
        "y": "kKnioMwy_0YF9luRABJ3oslTXSSA2aNbrZrj-Hp8lUA",
        "d": "Ha2mATm6MnJojdwD-FAUMdvXwbo8oCmzpIBCDOXTe_8"
    }
```
You will get other values for the x,y and d parameters with virtual certainty.

## JSON Web Signature

We will use the just now created web key to generate a digital signature of some JSON file containing a JSON object:
```
    Path path = Path.of("json", "my-json-file.json");
    JsonObject jsonObject;
    try (JsonReader jsonReader = Json.createReader(new FileInputStream(path.toFile()))) {
        jsonObject = jsonReader.readObject();
    }
    JWSCompactSerialization compactSerialization = JWS.createSignature()
            .webkey(jsonWebKeyPair)
            .typ("JOSE")
            .payload(jsonObject)
            .sign();
```
The JSON representation of the accompanying JOSE header is subsequently shown:
```
    {
        "alg": "ES256",
        "typ": "JOSE",
        "kid": "45dc44ba-531b-4039-8980-c28c0ac6e690",
        "jwk": {
            "kty": "EC",
            "kid": "45dc44ba-531b-4039-8980-c28c0ac6e690",
            "crv": "secp256r1 [NIST P-256,X9.62 prime256v1] (1.2.840.10045.3.1.7)",
            "x": "_NpBXbIUH-OcV4XirIcKBaXafX895eKTyekhLo9VDYA",
            "y": "kKnioMwy_0YF9luRABJ3oslTXSSA2aNbrZrj-Hp8lUA"
        }
    }
```
The JWS signature given in the JWS compact serialization format can be validated as follows:
```
    JsonWebPublicKey jsonWebPublicKey = JsonWebPublicKey.fromJson(compactSerialization.joseHeader().getJsonObject("jwk"));
    boolean validated = JWS.createValidator()
            .compactSerialization(compactSerialization)
            .key(jsonWebPublicKey)
            .validate();    
    assert validated == true;
```
