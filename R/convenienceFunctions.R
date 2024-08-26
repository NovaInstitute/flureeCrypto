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
  # Ensure n is less than or equal to 64 (SHA3-512 produces 64 bytes)
  stopifnot(n <= 64)

  # Convert the key to raw bytes if it's a string
  if (is.character(key)) {
    key <- charToRaw(key)
  }

  # Compute the SHA3-512 hash
  hash_512 <- digest(key, algo = "sha512", serialize = FALSE, raw = TRUE)

  # Return the first n bytes of the hash
  return(hash_512[1:n])
}


#' Coerce Input Format
#'
#' This function checks whether the input is a string or bytes and returns a label indicating the format.
#'
#' @param x The input to be checked, which can be a character string or raw vector.
#'
#' @return A character string indicating the format, either "string" or "bytes".
#'
#' @examples
#' input_format <- coerce_input_format("Hello, world!")
#' print(input_format)  # Should print "string"
#'
#' input_format <- coerce_input_format(as.raw(1:5))
#' print(input_format)  # Should print "bytes"
#'
#' @export
coerce_input_format <- function(x) {
  if (is.character(x)) {
    return("string")
  } else if (is.raw(x)) {
    return("bytes")
  } else {
    stop("Unsupported input format")
  }
}


#' Convert a String to a Byte Array
#'
#' This function normalizes a string and then converts it to a byte array (raw vector).
#' If the input is already a byte array, it returns the original value.
#'
#' @param s A character string or a raw vector. The string will be normalized and converted to a byte array.
#'
#' @return A raw vector representing the byte array.
#'
#' @examples
#' byte_array <- string_to_byte_array("Café")
#' print(byte_array)
#'
#' raw_input <- as.raw(1:5)
#' byte_array <- string_to_byte_array(raw_input)
#' print(byte_array)  # Should print the original raw vector
#'
#' @import stringi
#' @export
string_to_byte_array <- function(s) {
  if (is.raw(s)) {
    return(s)   # Input is already a raw vector; return as-is
  } else if (is.character(s)) {
    # Normalize the string using the previously defined function
    normalized_string <- normalize_string(s)
    # Convert the normalized string to a raw vector (byte array)
    raw_vector <- charToRaw(normalized_string)
    # Convert raw vector to numeric vector (ASCII values)
    byte_array <- as.numeric(raw_vector)
    return(byte_array)
  } else {
    stop("Unsupported input type. Expected a string or a raw vector.")
  }
}


#' Convert a Byte Array to a String
#'
#' This function converts a byte array (raw vector) back into a string.
#'
#' @param s A raw vector representing the byte array to be converted to a string.
#'
#' @return A character string that corresponds to the byte array.
#'
#' @examples
#' raw_input <- charToRaw("Hello, world!")
#' string_output <- byte_array_to_string(raw_input)
#' print(string_output)  # Should print "Hello, world!"
#'
#' @export
byte_array_to_string <- function(s) {
  if (is.raw(s)) {
    # Input is already a raw vector, convert to string
    return(rawToChar(s))
  } else if (is.numeric(s)) {
    # Input is a numeric vector, convert to raw vector first
    raw_vector <- as.raw(s)
    return(rawToChar(raw_vector))
  } else {
    stop("Unsupported input type. Expected a raw vector or numeric vector.")
  }
}
