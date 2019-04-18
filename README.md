# KeyManagement
An application that simulates key management and distribution through certificates.

## Usage
For building files a simple javac followed by java is sufficient.

**[User.java:](/src/main/java/KeyManagement/core/User.java)**

```console
java core.User <ElGamal key size> <hash>
```

**Example:**

```console
$ java User 64 SHA-256

p = 13077187765650690481 g = 2
message 5007984607371391725
privateKey = 3898324131801293726 publicKey = 2957049132285488588
Verified
```