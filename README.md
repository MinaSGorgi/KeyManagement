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

q = 13902681838148292169 a = 2
message 3222096348953224391
privateKey = 5228842514499910612 publicKey = 11364917247844670665
Verified
```