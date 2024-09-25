#' Check if a value is a valid byte
#'
#' Determines if a given value is a valid byte (an integer between 0 and 255).
#'
#' @param b A number to check.
#' @return TRUE if the value is a valid byte, otherwise FALSE.
#' @export
byte_check <- function(b) {
  is.numeric(b) && b >= 0 && b <= 255 && b == floor(b)
}

#' Check if a vector contains valid bytes
#'
#' Determines if all elements in a vector are valid bytes.
#'
#' @param bytes A numeric vector.
#' @return TRUE if all elements are valid bytes, otherwise FALSE.
#' @export
bytes_check <- function(bytes) {
  all(sapply(bytes, byte_check))
}

#' Compare two byte arrays
#'
#' Compares two byte arrays for equality. Returns FALSE if they are of different lengths or if either contains invalid bytes.
#'
#' @param ba1 A numeric vector (byte array).
#' @param ba2 A numeric vector (byte array).
#' @return TRUE if the byte arrays are identical, otherwise FALSE.
#' @export
compare_bytes <- function(ba1, ba2) {
  if (length(ba1) != length(ba2)) {
    return(FALSE)
  }
  if (!bytes_check(ba1) || !bytes_check(ba2)) {
    return(FALSE)
  }
  all(ba1 == ba2)
}

#' PKCS7 Encode
#'
#' Pads a message using PKCS7 padding based on the provided block size.
#'
#' @param k An integer representing the block size.
#' @param m A numeric vector representing the message (byte array) to pad.
#' @return A numeric vector representing the padded message.
#' @export
pkcs7_encode <- function(k, m) {
  n <- k - (length(m) %% k)
  c(m, rep(n, n))
}

#' PKCS7 Decode
#'
#' Removes PKCS7 padding from a padded message. Throws an error if the padding is invalid.
#'
#' @param k An integer representing the block size.
#' @param m A numeric vector representing the padded message (byte array).
#' @return A numeric vector representing the original unpadded message.
#' @export
pkcs7_decode <- function(k, m) {
  len <- length(m)
  last_byte <- m[len]
  error <- last_byte > len || last_byte > k || last_byte == 0 || (len %% k != 0)
  
  if (error) {
    stop(paste("Invalid PKCS7 encoding:", paste(m, collapse = " ")))
  }
  
  computed <- rep(last_byte, last_byte)
  provided <- m[(len - last_byte + 1):len]
  
  if (!compare_bytes(computed, provided)) {
    stop("Padding doesn't match")
  }
  
  m[1:(len - last_byte)]
}
