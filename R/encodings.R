#' Pads a hexadecimal string with a leading zero if the length is odd
#'
#' @param hex A hexadecimal string
#' 
#' @return A padded hexadecimal string with a leading zero if necessary
#' 
#' @export
pad_hex <- function(hex) {
  if (nchar(hex) %% 2 == 1) {
    paste0("0", hex)
  } else {
    hex
  }
}

#' Convert BigInteger to Byte Array
#'
#' This function converts a GMP big integer to a raw byte array.
#'
#' @param bn A GMP big integer (from the `gmp` library in R).
#' @return A raw byte array representing the big integer.
#' @export
biginteger_to_bytes <- function(bn) {
  # Ensure it's a gmp bigz object
  if (!inherits(bn, "bigz")) {
    stop("bn must be a gmp::bigz object")
  }
  
  # Convert bigz to a string (base 16/hexadecimal)
  bn_hex <- as.character(bn, base = 16)
  
  # Pass the string to C
  .Call("biginteger_to_bytes", bn_hex)
}

#' Convert a big integer to a hexadecimal string
#'
#' @param bn A big integer value (as an R numeric or character)
#' @return A string representing the hexadecimal value of the big integer
#' @export
biginteger_to_hex <- function(bn) {
  # Ensure bn is of type biginteger
  if (!inherits(bn, "bigz")) {
    stop("Input must be a big integer.")
  }
  
  # Call the C function
  hex_string <- .Call("biginteger_to_hex_R", bn)  # Call to C function
  return(hex_string)
}


#' Convert the first byte of a raw byte vector to an integer
#'
#' @param the_bytes A raw byte vector
#' @return An integer representation of the first byte
byte_to_int <- function(the_bytes) {
  # Ensure the input is a raw byte vector
  if (!is.raw(the_bytes)) {
    stop("Input must be a raw byte vector.")
  }
  
  # Convert the first byte to an integer
  int_value <- as.integer(the_bytes[1])
  
  return(int_value)
}

#' Pads a string to a specified length with leading zeroes
#'
#' @param s A string
#' @param len The desired length of the string
#' 
#' @return A string padded with leading zeroes
pad_to_length <- function(s, len) {
  pad_len <- len - nchar(s)
  if (pad_len > 0) {
    paste0(strrep("0", pad_len), s)
  } else {
    s
  }
}
