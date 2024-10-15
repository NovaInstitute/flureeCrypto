library(gmp)
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

#' Convert a big integer to raw bytes
#'
#' @param bn A big integer value (as an R numeric or character)
#' @return A raw byte vector representing the big integer
#' @export
biginteger_to_bytes <- function(bn) {
  # Ensure bn is of type biginteger
  if (!inherits(bn, "bigz")) {
    stop("Input must be a big integer.")
  }
  
  # Call the C function
  len <- as.integer(0)  # Initialize length variable
  bytes_ptr <- .Call("biginteger_to_bytes_R", bn, len)  # Call to C function
  raw_bytes <- raw(bytes_ptr)  # Convert to raw type
  return(raw_bytes)
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

#' Converts a big integer to bytes
#'
#' @param bn A big integer value (can be numeric or character)
#' @param len Optional length of byte array (if not provided, the minimum length is used)
#' @return A raw byte vector representing the big integer
#' @export
biginteger_to_bytes <- function(bn, len = NULL) {
  # Convert big integer to hexadecimal representation
  bn_hex <- sprintf("%x", bn)
  
  # Add leading zero if the hex string has odd length (to ensure complete bytes)
  if (nchar(bn_hex) %% 2 != 0) {
    bn_hex <- paste0("0", bn_hex)
  }
  
  # Convert hex string to raw bytes
  raw_bytes <- as.raw(as.integer(sapply(seq(1, nchar(bn_hex), by = 2), function(i) {
    substr(bn_hex, i, i+1)
  }), 16))
  
  # If a specific length is provided, pad or trim the raw bytes
  if (!is.null(len)) {
    if (length(raw_bytes) < len) {
      # Pad with leading zeros
      raw_bytes <- c(rep(as.raw(0), len - length(raw_bytes)), raw_bytes)
    } else {
      # Trim the raw bytes to the specified length
      raw_bytes <- raw_bytes[(length(raw_bytes) - len + 1):length(raw_bytes)]
    }
  }
  
  return(raw_bytes)
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
