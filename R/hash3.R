
#' General SHA3 Hashing Function
#'
#' This function calculates a SHA3 hash of the specified size (256 or 512 bits).
#'
#' @param ba A raw vector representing the byte array to be hashed.
#' @param hash_size The size of the hash, either 256 or 512 bits.
#'
#' @return A raw vector representing the hash.
#'
#' @examples
#' hash256 <- hash3(charToRaw("Hello, world!"), 256)
#' print(hash256)  # Outputs the SHA3-256 hash as a raw vector
#'
#' hash512 <- hash3(charToRaw("Hello, world!"), 512)
#' print(hash512)  # Outputs the SHA3-512 hash as a raw vector
#'
#' @import openssl
#' @export
hash3 <- function(ba, hash_size) {
  stopifnot(hash_size %in% c(256, 512))  # Ensure the hash size is either 256 or 512

  if (hash_size == 256) {
    return(openssl::sha3(ba, size = 256))
  } else if (hash_size == 512) {
    return(openssl::sha3(ba, size = 512))
  } else {
    stop("Unsupported hash size. Only 256 and 512 are supported.")
  }
}

#' SHA3-256 Hashing Function
#'
#' This function calculates the SHA3-256 hash of the input byte array.
#'
#' @param ba A raw vector representing the byte array to be hashed.
#'
#' @return A raw vector representing the SHA3-256 hash.
#'
#' @examples
#' hash256 <- sha3_256(charToRaw("Hello, world!"))
#' print(hash256)  # Outputs the SHA3-256 hash as a raw vector
#'
#' @export
sha3_256 <- function(ba) {
  return(hash3(ba, 256))
}

#' SHA3-512 Hashing Function
#'
#' This function calculates the SHA3-512 hash of the input byte array.
#'
#' @param ba A raw vector representing the byte array to be hashed.
#'
#' @return A raw vector representing the SHA3-512 hash.
#'
#' @examples
#' hash512 <- sha3_512(charToRaw("Hello, world!"))
#' print(hash512)  # Outputs the SHA3-512 hash as a raw vector
#'
#' @export
sha3_512 <- function(ba) {
  return(hash3(ba, 512))
}


# Load the necessary packages
library(openssl)
library(sodium)
library(base64enc)

#' SHA3-256 Hashing Function with Output Format
#'
#' This function calculates the SHA3-256 hash of the input and returns it in the specified output format.
#'
#' @param x The input to be hashed, either a character string or a raw vector.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#' @param input_format The format of the input. Options are "string" or "bytes".
#'
#' @return A character string representing the SHA3-256 hash in the specified format.
#'
#' @examples
#' sha3_256("Hello, world!")
#' sha3_256(charToRaw("Hello, world!"), output_format = "base64")
#'
#' @export
sha3_256 <- function(x, output_format = "hex", input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the SHA3-256 hash
  hash_raw <- hash3(x, 256)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}

#' SHA3-256 Hashing Function with Normalization
#'
#' This function normalizes a string and then computes its SHA3-256 hash.
#'
#' @param s The string to be hashed.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#'
#' @return A character string representing the SHA3-256 hash in the specified format.
#'
#' @examples
#' hash_hex <- sha3_256_normalize("Café")
#' print(hash_hex)  # Outputs the SHA3-256 hash of the normalized string in hexadecimal format
#'
#' hash_base64 <- sha3_256_normalize("Café", output_format = "base64")
#' print(hash_base64)  # Outputs the SHA3-256 hash of the normalized string in base64 format
#'
#' @export
sha3_256_normalize <- function(s, output_format = "hex") {
  # Normalize the string
  normalized_string <- normalize_string(s)

  # Compute the SHA3-256 hash of the normalized string
  hash_result <- sha3_256(normalized_string, output_format = output_format, input_format = "string")

  return(hash_result)
}

#' SHA3-512 Hashing Function with Output Format
#'
#' This function calculates the SHA3-512 hash of the input and returns it in the specified output format.
#'
#' @param x The input to be hashed, either a character string or a raw vector.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#' @param input_format The format of the input. Options are "string" or "bytes".
#'
#' @return A character string representing the SHA3-512 hash in the specified format.
#' @import base64enc
#' @import openssl
#' @import sodium
#' @examples
#' sha3_512("Hello, world!")
#' sha3_512(charToRaw("Hello, world!"), output_format = "base64")
#'
#' @export
sha3_512 <- function(x, output_format = "hex", input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the SHA3-512 hash
  hash_raw <- hash3(x, 512)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}

#' SHA3-512 Hashing Function with Normalization
#'
#' This function normalizes a string and then computes its SHA3-512 hash.
#'
#' @param s The string to be hashed.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#'
#' @return A character string representing the SHA3-512 hash in the specified format.
#'
#' @examples
#' hash_hex <- sha3_512_normalize("Café")
#' print(hash_hex)  # Outputs the SHA3-512 hash of the normalized string in hexadecimal format
#'
#' hash_base64 <- sha3_512_normalize("Café", output_format = "base64")
#' print(hash_base64)  # Outputs the SHA3-512 hash of the normalized string in base64 format
#'
#' @export
sha3_512_normalize <- function(s, output_format = "hex") {
  # Normalize the string
  normalized_string <- normalize_string(s)

  # Compute the SHA3-512 hash of the normalized string
  hash_result <- sha3_512(normalized_string, output_format = output_format, input_format = "string")

  return(hash_result)
}

