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
#' hash_string_key("example-key", 32)
#' hash_string_key(charToRaw("example-key"), 16)
#'
#' @import digest sodium
#' @export

hash_string_key <- function(key, n = 32) {
  # Ensure n is less than or equal to 64 (since SHA3-512 produces 64 bytes)
  stopifnot(n <= 64)
  
  # Convert the key to raw bytes if it's a string
  if (is.character(key)) {
    key <- charToRaw(key)
  }
  
  # Compute the SHA3-512 hash and convert to binary array
  hash_512 <- sha3_512(key)
  hash_512 <- hex2bin(hash_512)
  
  # Return the first n bytes of the hash
  return(hash_512[1:n])
}

