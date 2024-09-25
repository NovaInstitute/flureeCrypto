#' Pads a hexadecimal string with a leading zero if the length is odd
#'
#' @param hex A hexadecimal string
#' @return A padded hexadecimal string with a leading zero if necessary
pad_hex <- function(hex) {
  if (nchar(hex) %% 2 == 1) {
    paste0("0", hex)
  } else {
    hex
  }
}

#' Converts a big integer to a hexadecimal string
#'
#' @param bn A big integer value (secp256k1 bigint)
#' @return A hexadecimal string representing the big integer
biginteger_to_hex <- function(bn) {
  as.character(bn, base = 16)
}

#' Converts a hexadecimal string to a big integer
#'
#' @param hex A hexadecimal string
#' @return A big integer converted from the hexadecimal string
hex_to_biginteger <- function(hex) {
  as.bigz(hex, base = 16)
}

#' Converts a big integer to bytes
#'
#' @param bn A big integer value
#' @param len Optional length of byte array
#' @return A raw byte vector of the big integer
biginteger_to_bytes <- function(bn, len = NULL) {
  raw_bn <- as.raw(as.bigz(bn))
  if (!is.null(len) && length(raw_bn) < len) {
    raw_bn <- c(rep(as.raw(0), len - length(raw_bn)), raw_bn)
  }
  raw_bn
}

#' Converts bytes to a big integer
#'
#' @param bytes A raw byte vector
#' @return A big integer value
bytes_to_biginteger <- function(bytes) {
  as.bigz(bytes, base = 256)
}

#' Pads a string to a specified length with leading zeroes
#'
#' @param s A string
#' @param len The desired length of the string
#' @return A string padded with leading zeroes
pad_to_length <- function(s, len) {
  pad_len <- len - nchar(s)
  if (pad_len > 0) {
    paste0(strrep("0", pad_len), s)
  } else {
    s
  }
}

#' Computes an elliptic curve point for a y-coordinate parity and x-coordinate
#'
#' @param y_even A boolean indicating whether the y-coordinate is even
#' @param x_coordinate The x-coordinate of the point
#' @param curve The elliptic curve parameters
#' @return The computed elliptic curve point
compute_point <- function(y_even, x_coordinate, curve) {
  # Placeholder for actual computation based on libsecp256k1 elliptic curve functions
  x <- as.bigz(x_coordinate, base = 16)
  # Assume a dummy y value here for illustration
  y <- if (y_even) x else x + 1 # Not an actual implementation
  list(x = x, y = y)
}

#' Encodes x and y coordinates in hex to X9.62 format with optional compression
#'
#' @param x_coord The x-coordinate in hexadecimal
#' @param y_coord The y-coordinate in hexadecimal
#' @param compressed A boolean indicating if compression is to be applied (default: TRUE)
#' @return The X9.62 encoded public key
x962_encode <- function(x_coord, y_coord, compressed = TRUE) {
  x_hex <- pad_hex(x_coord)
  y_hex <- pad_hex(y_coord)
  if (!compressed) {
    paste0("04", x_hex, y_hex)
  } else {
    y_even <- (as.bigz(y_hex, base = 16) %% 2) == 0
    prefix <- if (y_even) "02" else "03"
    paste0(prefix, pad_to_length(x_hex, 64))
  }
}

#' Decodes a DER-encoded ECDSA signature
#'
#' @param ecdsa The hexadecimal-encoded ECDSA signature
#' @return A list with R, S, and recovery values
DER_decode_ECDSA_signature <- function(ecdsa) {
  # Placeholder for actual DER decoding logic
  R <- as.bigz(substr(ecdsa, 1, 64), base = 16)
  S <- as.bigz(substr(ecdsa, 65, 128), base = 16)
  recover <- as.integer(substr(ecdsa, 129, 130))
  list(R = R, S = S, recover = recover)
}