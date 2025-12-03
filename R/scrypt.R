#' Generate Random Bytes
#'
#' @description
#' Generates a cryptographically secure random byte array of the specified size.
#' This function uses OpenSSL's random number generator to produce high-quality
#' random bytes suitable for cryptographic operations like salts and keys.
#'
#' @param size Integer. The size of the random byte array to generate.
#' 
#' @return A raw vector containing the random bytes.
#' 
#' @examples
#' \dontrun{
#' # Generate 16 random bytes for a salt
#' salt <- random_bytes(16)
#' # Generate 32 random bytes for a key
#' key <- random_bytes(32)
#' }
#' 
random_bytes <- function(size) {
  openssl::rand_bytes(size)
}

#' Encrypt Using scrypt
#'
#' @description
#' Encrypts a message (raw bytes) using a specified salt and scrypt parameters.
#' Returns the encrypted message in bytes directly. The encrypted output can be
#' verified using the same salt and scrypt parameters.
#'
#' @param msg A raw vector or character string containing the message to encrypt.
#' @param salt A numeric vector containing the salt to use (default random 16 bytes).
#' @param n Integer. CPU/memory cost factor (default 32768).
#' @param r Integer. Block size factor (default 8).
#' @param p Integer. Parallelization factor (default 1).
#' @param dk_len Integer. Length of the derived key (default 32).
#' 
#' @return A raw vector containing the encrypted message.
#' 
#' @export
scrypt_encrypt <- function(msg, salt = random_bytes(16), n = 32768, r = 8, p = 1, dk_len = 32) {
  if (is.character(msg)) {
    msg_bytes <- charToRaw(msg)
  } else {
    msg_bytes <- msg
  }
  salt <- as.raw(map_signed_to_unsigned(salt))
  encrypted <- scrypt::scrypt(msg_bytes, salt, n, r, p, length = dk_len)
  return(bin2hex(encrypted))
}

#' Check Encrypted Message
#'
#' @description
#' Compares a raw message (bytes) with a previously encrypted message (bytes) that was encrypted
#' using the specified salt and scrypt parameters. Returns TRUE if the two match, otherwise FALSE.
#'
#' @param msg A raw vector or character string containing the original message.
#' @param encrypted A raw vector containing the encrypted message.
#' @param salt A numeric vector containing the salt used during encryption.
#' @param n Integer. CPU/memory cost factor used during encryption (default 32768).
#' @param r Integer. Block size factor used during encryption (default 8).
#' @param p Integer. Parallelization factor used during encryption (default 1).
#' 
#' @return Logical. TRUE if the raw message matches the encrypted message, FALSE otherwise.
#' 
#' @export
scrypt_check <- function(msg, encrypted, salt, n = 32768, r = 8, p = 1) {
  if (is.character(msg)) {
    msg_bytes <- charToRaw(msg)
  } else {
    msg_bytes <- msg
  }
  dk_len <- (nchar(encrypted))/2
  test_encrypted <- scrypt_encrypt(msg_bytes, salt, n, r, p, dk_len)
  identical(encrypted, test_encrypted)
}
