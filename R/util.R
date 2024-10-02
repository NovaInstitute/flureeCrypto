#' Hash a String Key using SHA3-512 and Return Specified Bytes
#'
#' This function takes a string key, hashes it using the SHA3-512 algorithm, and returns the first `n` bytes of the hash.
#'
#' @param key A character string or raw vector to be hashed. If it's a string, it will be converted to raw bytes.
#' @param n An integer specifying the number of bytes to return from the hash. Must be between 1 and 64 (default is 32).
#'
#' @return A raw vector containing the first `n` bytes of the SHA3-512 hash.
#'
#' @examples
#' hash_string_key("hello", 32)
#' hash_string_key(charToRaw("example-key"), 16)
#' # fluree.crypto.util=> (hash-string-key "hello" 32)
#' # (117 -43 39 -61 104 -14 -17 -24 72 -20 -10 -80 115 -93 103 103 -128 8 5 -23 -18 -14 -79 -123 125 95 -104 79 3 110 -74 -33)
#' # fluree.crypto.util=> (hash-string-key "example-key" 16)
#' # (-1 115 100 -51 32 13 -97 54 15 -13 -70 41 -90 -10 93 4)
#' @import digest sodium openssl
#' @export

# Function to compute the SHA3-512 hash and return the first n bytes
hash_string_key <- function(key, n = 32) {
  # Ensure n is less than or equal to 64 (since SHA3-512 produces 64 bytes)
  stopifnot(n <= 64)

  # Convert the key to raw bytes if it's a string
  if (is.character(key)) {
    key <- charToRaw(key)
  }

  # Compute the SHA3-512 hash
  hash_512 <- openssl::sha3(key, size = 512)

  # Convert the raw bytes to integers
  raw_bytes <- as.integer(hash_512)

  # Convert unsigned integers to signed integers for the first n bytes
  signed_bytes <- ifelse(raw_bytes > 127, raw_bytes - 256, raw_bytes)

  # Return the first n signed bytes of the hash
  return(signed_bytes[1:n])
}



