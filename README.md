# KeyManagement
An application that simulates key management and distribution through certificates.

## Usage
For building files a simple javac followed by java is sufficient.

**[User.java:](/src/main/java/KeyManagement/core/User.java)**

```console
java core.User <hash> <ElGamal key size> <message>
```

**Example:**

```console
$ java core.User SHA-256 1024 123456789

Sucess Test...
Verified
decrypted message = 123456789
Dectypted Succesfully

Gamal Fail Test...
Not Verified
decrypted message = 123456789
Dectypted Succesfully
```