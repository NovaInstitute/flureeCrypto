
#' SHA-256 Hashing Function
#'
#' This function calculates the SHA-256 hash of the input.
#'
#' @param x The input to be hashed, either a character string or a raw vector.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#' @param input_format The format of the input. Options are "string" or "bytes".
#'
#' @return A character string representing the SHA-256 hash in the specified format.
#'
#' @examples
#' sha2_256("Hello, world!")
#' sha2_256(charToRaw("Hello, world!"), output_format = "base64")
#'
#' @import openssl sodium
#' @export
sha2_256 <- function(x, output_format = "hex", input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the SHA-256 hash
  hash_raw <- sha256(x)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}

#' SHA-256 Hashing Function with Normalization
#'
#' This function normalizes a string and then computes its SHA-256 hash.
#'
#' @param s The string to be hashed.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#'
#' @return A character string representing the SHA-256 hash in the specified format.
#'
#' @examples
#' hash_hex <- sha2_256_normalize("Café")
#' print(hash_hex)  # Outputs the SHA-256 hash of the normalized string in hexadecimal format
#'
#' hash_base64 <- sha2_256_normalize("Café", output_format = "base64")
#' print(hash_base64)  # Outputs the SHA-256 hash of the normalized string in base64 format
#'
#' @export
sha2_256_normalize <- function(s, output_format = "hex") {
  # Normalize the string
  normalized_string <- normalize_string(s)

  # Compute the SHA-256 hash of the normalized string
  hash_result <- sha2_256(normalized_string, output_format = output_format, input_format = "string")

  return(hash_result)
}

#' SHA-512 Hashing Function
#'
#' This function calculates the SHA-512 hash of the input.
#'
#' @param x The input to be hashed, either a character string or a raw vector.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#' @param input_format The format of the input. Options are "string" or "bytes".
#'
#' @return A character string representing the SHA-512 hash in the specified format.
#'
#' @examples
#' sha2_512("Hello, world!")
#' sha2_512(charToRaw("Hello, world!"), output_format = "base64")
#'
#' @import openssl sodium
#' @export
sha2_512 <- function(x, output_format = "hex", input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the SHA-512 hash
  hash_raw <- sha512(x)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}

#' SHA-512 Hashing Function with Normalization
#'
#' This function normalizes a string and then computes its SHA-512 hash.
#'
#' @param s The string to be hashed.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#'
#' @return A character string representing the SHA-512 hash in the specified format.
#'
#' @examples
#' hash_hex <- sha2_512_normalize("Café")
#' print(hash_hex)  # Outputs the SHA-512 hash of the normalized string in hexadecimal format
#'
#' hash_base64 <- sha2_512_normalize("Café", output_format = "base64")
#' print(hash_base64)  # Outputs the SHA-512 hash of the normalized string in base64 format
#'
#' @export
sha2_512_normalize <- function(s, output_format = "hex") {
  # Normalize the string
  normalized_string <- normalize_string(s)

  # Compute the SHA-512 hash of the normalized string
  hash_result <- sha2_512(normalized_string, output_format = output_format, input_format = "string")

  return(hash_result)
}

# Load the necessary packages
library(digest)
library(sodium)

#' SHA3-256 Hashing Function
#'
#' This function calculates the SHA3-256 hash of the input.
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
#' @import digest sodium
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
  hash_raw <- digest::digest(x, algo = "sha3-256", serialize = FALSE, raw = TRUE)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}

