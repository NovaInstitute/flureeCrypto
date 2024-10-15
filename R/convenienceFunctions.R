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

#' Map Excess-127 Function
#'
#' This function takes a vector of integers and transforms each element:
#' If an element is greater than 127, it subtracts 256 from that element;
#' otherwise, it leaves the element unchanged. This represents an Excess-127 format.
#'
#' @param iv A numeric vector containing integer values.
#' @return A numeric vector with transformed values.
#' @examples
#' # Example usage
#' iv <- c(130, 120, 127, 255)
#' result <- map_excess_127(iv)
#' print(result)  # Output: [1] -126 120 127 -1
map_excess_127 <- function(ba) {
  result <- ifelse(ba > 127, ba - 256, ba)
  return(result)
}

#' Map Signed to Unsigned Function
#'
#' This function takes a vector of integers and replaces negative integers
#' with their positive counterparts (by adding 256) while leaving other 
#' integers unchanged.
#'
#' @param salt_bytes A numeric vector containing integer values.
#' @return A numeric vector with negative integers replaced.
#' @examples
#' # Example usage
#' salt_bytes <- c(-5, 0, 10, -128, 255)
#' result <- map_signed_to_unsigned(salt_bytes)
#' print(result)  # Output: [1] 251 0 10 128 255
map_signed_to_unsigned <- function(ba) {
  result <- ifelse(ba < 0, ba + 256, ba)
  return(result)
}