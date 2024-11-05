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
#' sha2_256("hello")
#' sha2_256(charToRaw("hello"), output_format = "base64")
#' # => (println (alphabase/bytes->hex (sha2-256 (.getBytes "hello"))))
#' # 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
#'
#' @import openssl sodium
#' @export
sha2_256 <- function(x, output_format = c("hex", "base64", "raw")[1], input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(x)
  }

  # Calculate the SHA-256 hash
  hash_raw <- digest::digest(x, algo = "sha256", serialize = FALSE, raw = TRUE)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else if (output_format == "raw") {
    return(hash_raw)
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
#' sha2_512("hello")
#' sha2_512(charToRaw("Hello, world!"), output_format = "base64")
#' ## => (println (alphabase/bytes->hex (sha2-512 (.getBytes "hello"))))
#' ## 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
#' ## crypto.sha2_512("hi");
#' ## returns: 150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197.
#' @import openssl sodium
#' @export
sha2_512 <- function(x, output_format = c("hex", "base64", "raw")[1], input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(x)
  }

  # Calculate the SHA-512 hash
  hash_raw <- digest::digest(x, algo = "sha512", serialize = FALSE, raw = TRUE)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else if (output_format == "raw") {
    return(hash_raw)
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

