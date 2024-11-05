
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
#' sha3_256("hello")
#' sha3_256("hello", output_format =  "raw")
#' sha3_256(charToRaw("hello"), output_format = "base64")
#'
#' @import digest sodium
#' @export
sha3_256 <- function(x, output_format = c("hex", "base64", "raw")[1], input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(x)
  }

  # Calculate the SHA3-256 hash
  hash_raw <- openssl::sha3(x, size = 256)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else if (output_format == "raw") {
    return(hash_raw)  # Return raw bytes
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
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
#' sha3_512("hello")
#' sha3_512(charToRaw("hello"), output_format = "base64")
#' # fluree.crypto.sha3=> (println (alphabase/bytes->hex (sha3-512 (.getBytes "hello"))))
#' # 75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976
#' @export
sha3_512 <- function(x, output_format = c("hex", "base64", "raw")[1], input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(x)
  }

  # Calculate the SHA3-512 hash
  hash_raw <- openssl::sha3(x, size = 512)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else if (output_format == "raw") {
    return(hash_raw)  # Return raw bytes
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
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
