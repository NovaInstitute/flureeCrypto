## Cryptography Library for Fluree implemented in R

A collection of R cryptography functions for Fluree.  This package is merely an implementation/translation of the "fluree.crypto" Clojure function library. This library can be found [here](https://github.com/fluree/fluree.crypto).

## Utility Functions

### Normalize String

- Arguments: `string`
- Returns: `string`

Normalizes string using the NKFC standard to ensure consistent hashing.

`normalApple <- normalize_string("\u0041\u030apple")`

For example:

`sha2_256("\u0041\u030apple")` results in `6e9288599c1ff90127459f82285327c83fa0541d8b7cd215d0cd9e587150c15f`.

But when using the normalized version of the string:

`sha2_256_normalize(normalApple)` results in `58acf888b520fe51ecc0e4e5eef46c3bea3ca7df4c11f6719a1c2471bbe478bf`.

### String to Byte Array

- Arguments: `string` or `byte-array`
- Returns: `byte-array`

This functions normalizes a string and returns a byte-array. If it is already a byte-array, it returns itself.

For example:

`string_to_byte_array("hi there")` results in `[104, 105, 32, 116, 104, 101, 114, 101]`.


### Byte Array to String

- Arguments: `byte-array`
- Returns: `string`

This functions takes a byte-array and returns a string.

For example:

`byte_array_to_string(c(104, 105, 32, 116, 104, 101, 114, 101))` results in `hi there`.

## Cryptography functions

Some of the functions listed below make use of the external libsecp256k1 C library which can be found [here](https://github.com/bitcoin-core/secp256k1). In these cases wrapper functions were written in R to ensure ease of use.  The R wrapper functions call on C functions that leverage the external library to speed up the cryptographic operations.

### Generate Key Pair

- Arguments: `none` or `private-key-as-hex-string`
- Returns: `{ [[1]] "private-key-as-hex-string", [[2]] "public-key-as-hex-string" } `

This function will return a list with a public and private key pair:

`generate_keypair()` will return a valid public-private key pair.

For example:

```
[[1]]
[1] "4a32ac7297e99907965e188add1887bd7b9a226e33c7a014d7319a6abad35ea7"

[[2]]
[1] "025f8057c12fd0793a355b823ab74ed713a57626452a9cacef7b907197127581be"
```

You can also call this function with a private key already provided. The function then passes the private key to the corresponding C function which derives the corresponding public key.

For example:

`generate_keypair("6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")`

will return:

```
[[1]]
[1] "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"

[[2]]
[1] "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
```

### Public Key from Private

- Arguments: `private-key-as-hex-string`
- Returns: `public-key-as-hex-string`

Given a private key, this returns a public key.

For example:

`public_key_from_private("6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")`

will return: `02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391`.

### Account Id from Private

- Arguments: `private-key-as-hex-string`
- Returns: `account-id`

Given a private key, this will return an account id.

For example:

`account_id_from_private("6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")`

will return `TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV`.

### Account Id from Public

- Arguments: `public-key-as-hex-string`
- Returns: `account-id`

Given a public key, this will return an account id.

For example:

`account_id_from_public("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391")`

This will return `TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV`.

### Sign Message

- Arguments: `message, private-key-as-hex-string`
- Returns: `signature`

Given a message and a private key, this will return a signature.

```
message <- "hi there"
privateKey <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"

sign_message(message, privateKey)
```

This returns:

```
1b3046022100cbd32e463567fefc2f120425b0224d9d263008911653f50e83953f47cfbef3bc022100fcf81206277aa1b86d2667b4003f44643759b8f4684097efd92d56129cd89ea8
```
### Verify Signature

- Arguments: `public-key-as-hex-string, message, signature`
- Returns: `true` or `false`

Given a public key, message, and a signature, this function will return true or false depending on whether the given signature corresponds to the public key and message.

For example:

```
message <- "hi there"
privateKey <- "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
publicKey <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
signature <- sign_message(message, privateKey)

verify_signature(publicKey, message, signature);

```

This returns `true`.

### Public Key from Message

- Arguments: `message, signature`
- Returns: `public-key-as-hex-string`

Given a signature and corresponding message, this will return the appropriate public key.

For example:

```
message <- "hi there"
signature <- sign_message(message, "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")

public_key_from_message(message, signature)
```

This returns `02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391`.

### Account Id from Message

- Arguments: `message, signature`
- Returns: `account-id`

Given a signature and corresponding message, this will return the appropriate account ID.

For example:

```
message <- "hi there"
signature <- sign_message(message, "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")

account_id_from_message(message, signature)
```

This returns `TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV`.

## Hash functions

### SHA2 256

- Arguments: `string or byte-array` or `string or byte-array, output-format`.
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha2_256("hi")` 

returns: `8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4`.

### SHA2 256 Normalize

- Arguments: `string` or `string, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha2_256_normalize("hi")` 

returns: `8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4`.

### SHA2 512

- Arguments: `string or byte-array` or `string or byte-array, output-format`.
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha2_512("hi")` 

returns: `150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197`.

### SHA2 512 Normalize

- Arguments: `string` or `string, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha2_512_normalize("hi")` 

returns: `150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197`.

### SHA3 256

- Arguments: `string or byte-array` or `string or byte-array, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha3_256("hi")` 

returns: `b39c14c8da3b23811f6415b7e0b33526d7e07a46f2cf0484179435767e4a8804`.

### SHA3 256 Normalize

- Arguments: `string` or `string, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha3_256_normalize("hi")` 

returns: `b39c14c8da3b23811f6415b7e0b33526d7e07a46f2cf0484179435767e4a8804`.

### SHA3 512

- Arguments: `string or byte-array` or `string or byte-array, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha3_512("hi")` 

returns: `154013cb8140c753f0ac358da6110fe237481b26c75c3ddc1b59eaf9dd7b46a0a3aeb2cef164b3c82d65b38a4e26ea9930b7b2cb3c01da4ba331c95e62ccb9c3`.

### SHA3 512 Normalize

- Arguments: `string` or `string, output-format`
- Returns: By default `hex string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`sha3_512_normalize("hi")` 

returns: `154013cb8140c753f0ac358da6110fe237481b26c75c3ddc1b59eaf9dd7b46a0a3aeb2cef164b3c82d65b38a4e26ea9930b7b2cb3c01da4ba331c95e62ccb9c3`.

### RIPEMD-160

- Arguments: `string` or `string, output-format`.
- Returns: By default `hex-string`.

Valid output formats: `hex`, `bytes`, `base64`.

For example:

`ripemd_160("hi")` returns `242485ab6bfd3502bcb3442ea2e211687b8e4d89`.

## Encryption functions

### AES Encrypt

- Arguments: `message, key, iv` or `message, key, iv, output-format`
- Returns: By default `hex-string`.

Valid output formats: `hex`, `base64`, `none` (which just returns a raw vector).

For example:

```
initialization_vector <- c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
message = "hi"
key = "there"

aes_encrypt(message, key, initialization_vector)
```

This returns: `668cd07d1a17cc7a8a0390cf017ac7ef`.

### AES Decrypt

- Arguments: `x, , key, iv` or `x, key, iv, output-format`.
- Returns: By default `hex-string`.

For example:

```
initialization_vector <- c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
message = "hi"
key = "there"
encrypted = aes_encrypt(message, key, initialization_vector)

aes_decrypt(encrypted, key, initialization_vector)
```

will return: `hi`.

### Scrypt Encrypt

- Arguments: `message` or `message, salt` or `message, salt, n` or `message, salt, n, r, p` or `message, salt, n, r, p, dk-len`
- Returns: `hex-string`.

The arguments by default:

- `salt`: 16 random bytes
- `n`: 32,768
- `r`: 8
- `p`: 1
- `dk-len`: 32

For example:

```
salt_bytes = c(172, 28, 242, 108, 175, 130, 214, 6, 249, 61, 244, 178, 34, 8, 13, 178)

scrypt_encrypt("hi", salt = salt_bytes)
```

This results in `57f93bcf926c31a9e2d2129da84bfca51eb9447dfe1749b62598feacaad657d4`.

### Scrypt Check

- Arguments: `message, encrypted, salt` or `message, encrypted, salt, n, r, p`
- Returns: `true` or `false`

The arguments by default:

- `n`: 32,768
- `r`: 8
- `p`: 1

For example: 

```
salt_bytes = c(172, 28, 242, 108, 175, 130, 214, 6, 249, 61, 244, 178, 34, 8, 13, 178)
encrypted = scrypt_encrypt("hi", salt = salt_bytes, 32768, 8, 1)

crypto.scryptCheck("hi", encrypted, salt, 32768, 8, 1)
```

should return `true`.


### Tests

The tests for this package were written using the `testthat` package in R. They can be run using `devtools::test()`.

### Building

Clone this repository locally into the directory of your choice.  Also clone the external [libsecp256k1](https://github.com/bitcoin-core/secp256k1) library into a directory of your choice. 

Build the `libsecp256k1` library using autotools as specified in the library's [ReadMe](https://github.com/bitcoin-core/secp256k1/blob/master/README.md).

Pay special attention to the `./configure` step as the "recovery" and "ecdh" modules need to be enabled. 

Once the external package has been built make sure the path to the library files ("libsecp256k1.2.dylib", "libsecp256k1.a", "libsecp256k1.dylib") and header files ("secp256k1.h", "secp256k1_ecdh.h", "secp256k1_recovery.h") are known and noted as these need to be specified in the R package as follows: 

Navigate to the "src" directory within the cloned repository. In the "Makevars" file the path to the "libsecp256k1" library needs to be specified.
Note that the R package is also dependent on the "gmp" library and the same steps will need to be taken to make sure the package "finds" its library files.

For example the contents of the Makevars file should look something like this:

```
PKG_LIBS = -L/opt/homebrew/lib -lsecp256k1 -L/opt/homebrew/lib -lgmp
PKG_CFLAGS = -I/opt/homebrew/include
```

Here the library files for both the "gmp" and "secp256k1" libraries can be found in the following directory:  `/opt/homebrew/lib` 
and their corresponding header files in:  `/opt/homebrew/include`.

Once the "Makevars" file is up to date the package can be built as one would normally do (with "Build" -> "Install" for example")
