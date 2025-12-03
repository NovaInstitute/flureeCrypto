#' Pads a hexadecimal string with a leading zero if the length is odd
#'
#' @description
#' This helper function ensures a hexadecimal string has an even number of characters
#' by prepending a zero if necessary. This is useful for byte alignment.
#'
#' @param hex A hexadecimal string
#' 
#' @return A padded hexadecimal string with a leading zero if necessary
#' 
#' @examples
#' pad_hex("abc")  # Returns "0abc"
#' pad_hex("abcd")  # Returns "abcd"
#' 
pad_hex <- function(hex) {
  if (nchar(hex) %% 2 == 1) {
    paste0("0", hex)
  } else {
    hex
  }
}

#' Convert BigInteger to Byte Array
#'
#' @description
#' This function converts a GMP big integer to a raw byte array by first
#' converting to hexadecimal and then calling a C function for conversion.
#'
#' @param bn A GMP big integer (from the `gmp` library in R).
#' @return A raw byte array representing the big integer.
#' 
#' @examples
#' \dontrun{
#' library(gmp)
#' bn <- as.bigz("123456789")
#' bytes <- biginteger_to_bytes(bn)
#' }
#' 
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
#' @description
#' This function converts a GMP big integer (bigz object) to its hexadecimal
#' string representation using a C function.
#'
#' @param bn A big integer value (bigz object from the gmp package)
#' @return A string representing the hexadecimal value of the big integer
#' 
#' @examples
#' \dontrun{
#' library(gmp)
#' bn <- as.bigz("123456789")
#' hex_str <- biginteger_to_hex(bn)
#' }
#' 
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
#' @description
#' This helper function extracts the first byte from a raw vector and
#' converts it to an integer value (0-255).
#'
#' @param the_bytes A raw byte vector
#' @return An integer representation of the first byte (0-255)
#' 
#' @examples
#' bytes <- charToRaw("hello")
#' first_byte <- byte_to_int(bytes)  # Returns 104 (ASCII 'h')
#' 
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
#' @description
#' This helper function pads a string with leading zeros to reach a specified length.
#' If the string is already at or exceeds the desired length, it is returned unchanged.
#'
#' @param s A string to be padded
#' @param len The desired length of the string
#' 
#' @return A string padded with leading zeroes to reach the specified length
#' 
#' @examples
#' pad_to_length("42", 5)  # Returns "00042"
#' pad_to_length("12345", 3)  # Returns "12345"
#' 
pad_to_length <- function(s, len) {
  pad_len <- len - nchar(s)
  if (pad_len > 0) {
    paste0(strrep("0", pad_len), s)
  } else {
    s
  }
}
