
#' Hash a string key 
#'
#' @description
#' This function takes a string key, hashes it using the SHA3-512 algorithm 
#' and returns the first `n` bytes of the resulting hash.
#'
#' @param key A character string or raw vector to be hashed.
#' @param n An integer specifying the number of bytes to return from the hash. Must be between 1 and 64 (default is 32).
#'
#' @return A raw vector containing the first `n` bytes of the SHA3-512 hash.
#'
#' @examples
#' # hash_string_key("hello", 32)
#' # hash_string_key(charToRaw("example-key"), 16)
#' 
#' @importFrom openssl sha3
#'
hash_string_key <- function(key, n = 32) {
  # Ensure n is less than or equal to 64 (since the SHA3-512 hash function produces 64 bytes)
  stopifnot(n <= 64)

  # Convert the key to raw bytes if it's a string
  if (is.character(key)) {
    key <- charToRaw(key)
  }

  # Compute the SHA3-512 hash
  hash_512 <- openssl::sha3(key, size = 512)
  # Convert the raw bytes to integers
  raw_bytes <- as.integer(hash_512)
  # Convert unsigned integers to signed integers for the first n bytes
  signed_bytes <- ifelse(raw_bytes > 127, raw_bytes - 256, raw_bytes)
  # Return the first n signed bytes of the hash
  return(signed_bytes[1:n])
}

#' Normalize a string
#'
#' @description
#' This function normalizes a string using the NFKC normalization form. 
#' The normalized form of the string will result in consistent hashing.
#'
#' @param s A character string to be normalized.
#'
#' @return A character string that has been normalized to the NFKC form.
#'
#' @examples
#' # normalized_string <- normalize_string("\u0041\u030apple")
#' # print(normalized_string)
#'
#' @importFrom stringi stri_trans_nfkc
#' 
#' @export
normalize_string <- function(s) {
  normalized <- stringi::stri_trans_nfkc(s)
  return(normalized)
}




#' Coerce input format
#'
#' @description
#' This function checks whether the input is a string or raw bytes and returns 
#' a label indicating the format.
#'
#' @param x The input to be checked, which can be a character string or raw vector.
#'
#' @return A character string indicating the format, either "string" or "bytes".
#'
#' @examples
#' # input_format <- coerce_input_format("Hello, world!")
#' # print(input_format)
#'
#' # input_format <- coerce_input_format(as.raw(1:5))
#' # print(input_format)
#'
coerce_input_format <- function(x) {
  if (is.character(x)) {
    return("string")
  } else if (is.raw(x)) {
    return("bytes")
  } else {
    stop("Unsupported input format")
  }
}


#' Convert a string to a byte array
#'
#' @description
#' This function normalizes a string and then converts it to a byte array.
#' If the input is already a byte array, it returns the original value.
#'
#' @param s A character string or a raw vector. The string will be normalized before being converted to a byte array.
#'
#' @return A raw vector representing the byte array.
#'
#' @examples
#' # byte_array <- string_to_byte_array("Åpple")
#' # print(byte_array)
#'
#' # raw_input <- as.raw(1:5)
#' # byte_array <- string_to_byte_array(raw_input)
#' # print(byte_array)
#'
#' @export
string_to_byte_array <- function(s) {
  if (is.raw(s)) {
    return(s)
  } else if (is.character(s)) {
    normalized_string <- normalize_string(s)
    raw_vector <- charToRaw(normalized_string)
    # Convert the raw vector to numeric/ASCII values
    byte_array <- as.numeric(raw_vector)
    return(byte_array)
  } else {
    stop("Unsupported input type. Expected a string or a raw vector.")
  }
}





#' Convert a byte array to a string
#'
#' @description
#' This function converts a byte array (raw vector) into a string.
#' 
#' @param v A raw vector representing the byte array to be converted to a string.
#'
#' @return A character string that corresponds to the byte array.
#'
#' @examples
#' # raw_input <- charToRaw("Hello, world!")
#' # string_output <- byte_array_to_string(raw_input)
#' # print(string_output)
#'
#' @export
byte_array_to_string <- function(v) {
  if (is.raw(s)) {
    # Input is already a raw vector, convert to string
    return(rawToChar(v))
  } else if (is.numeric(v)) {
    # Input is a numeric vector, convert to raw vector first
    raw_vector <- as.raw(v)
    return(rawToChar(raw_vector))
  } else {
    stop("Unsupported input type. Expected a raw vector or numeric vector.")
  }
}

#' Map excess-127
#'
#' @description
#' This function takes a vector of integers and transforms each element:
#' if an element is greater than 127, it subtracts 256 from that element
#' otherwise, it leaves the element unchanged. 
#' This represents the excess-127 format of signed bytes.
#'
#' @param v A numeric vector.
#' 
#' @return A numeric vector with transformed values.
#' 
#' @examples
#' # v <- c(130, 120, 127, 255)
#' # result <- map_excess_127(v)
#' # print(result)
#' 
map_excess_127 <- function(v) {
  result <- ifelse(v > 127, v - 256, v)
  return(result)
}

#' Map signed to unsigned bytes
#'
#' @description
#' This function takes a vector of integers and replaces negative integers
#' with their positive counterparts (by adding 256).
#'
#' @param v A numeric vector.
#' 
#' @return A numeric vector with negative integers replaced.
#' 
#' @examples
#' # v <- c(-5, 0, 10, -128, 255)
#' # result <- map_signed_to_unsigned(v)
#' # print(result)
#' 
map_signed_to_unsigned <- function(ba) {
  result <- ifelse(ba < 0, ba + 256, ba)
  return(result)
}
