
#' Hash a string key 
#'
#' @description
#' This function takes a string key, hashes it using the SHA3-512 algorithm 
#' and returns the first `n` bytes of the resulting hash. The bytes are returned
#' as signed integers (-128 to 127).
#'
#' @param key A character string or raw vector to be hashed.
#' @param n An integer specifying the number of bytes to return from the hash. Must be between 1 and 64 (default is 32).
#'
#' @return A numeric vector containing the first `n` bytes of the SHA3-512 hash as signed integers.
#'
#' @examples
#' # Hash a string key and get 32 bytes
#' hash_string_key("hello", 32)
#' # Hash a raw vector key and get 16 bytes
#' hash_string_key(charToRaw("example-key"), 16)
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
#' a label indicating the format. Used internally to determine how to process input data.
#'
#' @param x The input to be checked, which can be a character string or raw vector.
#'
#' @return A character string indicating the format, either "string" or "bytes".
#'
#' @examples
#' # Check format of a string
#' coerce_input_format("Hello, world!")  # Returns "string"
#' # Check format of a raw vector
#' coerce_input_format(charToRaw("Hello"))  # Returns "bytes"
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
  if (is.raw(v)) {
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
#' if an element is greater than 127, it subtracts 256 from that element,
#' otherwise, it leaves the element unchanged. 
#' This converts unsigned bytes (0-255) to signed bytes (-128 to 127).
#'
#' @param v A numeric vector of unsigned byte values (0-255).
#' 
#' @return A numeric vector with values converted to signed bytes (-128 to 127).
#' 
#' @examples
#' # Convert unsigned bytes to signed
#' v <- c(130, 120, 127, 255)
#' result <- map_excess_127(v)
#' # Returns: c(-126, 120, 127, -1)
#' 
map_excess_127 <- function(v) {
  result <- ifelse(v > 127, v - 256, v)
  return(result)
}

#' Map signed to unsigned bytes
#'
#' @description
#' This function takes a vector of integers and converts negative integers
#' (representing signed bytes) to their positive counterparts (unsigned bytes)
#' by adding 256. This converts signed bytes (-128 to 127) to unsigned bytes (0-255).
#'
#' @param ba A numeric vector of signed byte values (-128 to 127).
#' 
#' @return A numeric vector with negative integers converted to unsigned bytes (0-255).
#' 
#' @examples
#' # Convert signed bytes to unsigned
#' v <- c(-5, 0, 10, -128, 127)
#' result <- map_signed_to_unsigned(v)
#' # Returns: c(251, 0, 10, 128, 127)
#' 
map_signed_to_unsigned <- function(ba) {
  result <- ifelse(ba < 0, ba + 256, ba)
  return(result)
}
