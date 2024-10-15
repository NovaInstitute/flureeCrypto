#' Generate Random Bytes
#'
#' Generates a random byte array of the specified size.
#' This will work only in environments where random byte generation is supported.
#'
#' @param size Integer. The size of the random byte array to generate.
#' @return A raw vector containing the random bytes.
#' @export
random_bytes <- function(size) {
  openssl::rand_bytes(size)
}

#' Encrypt Using scrypt
#'
#' Encrypts a message (raw bytes) using a specified salt and scrypt parameters.
#' Returns the encrypted message in bytes directly. The encrypted output can be
#' verified using the same salt and scrypt parameters.
#'
#' @param raw A raw vector containing the message to encrypt.
#' @param salt A raw vector containing the salt to use (default random 16 bytes).
#' @param n Integer. CPU/memory cost factor (default 32768).
#' @param r Integer. Block size factor (default 8).
#' @param p Integer. Parallelization factor (default 1).
#' @param dk_len Integer. Length of the derived key (default 32).
#' @return A raw vector containing the encrypted message.
#' @export
encrypt <- function(raw, salt = random_bytes(16), n = 32768, r = 8, p = 1, dk_len = 32) {
  salt <- map_signed_to_unsigned(salt)
  scrypt::scrypt(raw, salt, n, r, p, length = dk_len)
}

#' Check Encrypted Message
#'
#' Compares a raw message (bytes) with a previously encrypted message (bytes) that was encrypted
#' using the specified salt and scrypt parameters. Returns TRUE if the two match, otherwise FALSE.
#'
#' @param raw A raw vector containing the original message.
#' @param encrypted A raw vector containing the encrypted message.
#' @param salt A raw vector containing the salt used during encryption.
#' @param n Integer. CPU/memory cost factor used during encryption (default 32768).
#' @param r Integer. Block size factor used during encryption (default 8).
#' @param p Integer. Parallelization factor used during encryption (default 1).
#' @return Logical. TRUE if the raw message matches the encrypted message, FALSE otherwise.
#' @export
check <- function(raw, encrypted, salt, n = 32768, r = 8, p = 1) {
  dk_len <- length(encrypted)
  salt <- map_signed_to_unsigned(salt)
  test_encrypted <- encrypt(raw, salt, n, r, p, dk_len)
  identical(encrypted, test_encrypted)
}
