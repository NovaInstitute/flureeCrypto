
#' RIPEMD-160 Hashing Function
#'
#' This function calculates the RIPEMD-160 hash of the input byte array.
#'
#' @param ba A raw vector representing the byte array to be hashed.
#'
#' @return A raw vector representing the RIPEMD-160 hash.
#' @import openssl
#' @examples
#' hash_ripemd160 <- ripemd_160(charToRaw("hi there!"))
#' print(bin2hex(hash_ripemd160))  # Outputs the RIPEMD-160 hash in hexadecimal format
#'
#' @export
ripemd_160 <- function(ba) {
  # Calculate the RIPEMD-160 hash
  hash_raw <- openssl::ripemd160(ba)

  return(hash_raw)
}

#' RIPEMD-160 Hashing Function with Output Format
#'
#' This function calculates the RIPEMD-160 hash of the input and returns it in the specified output format.
#'
#' @param x The input to be hashed, either a character string or a raw vector.
#' @param output_format The format of the output hash. Options are "hex" (default) or "base64".
#' @param input_format The format of the input. Options are "string" or "bytes".
#'
#' @return A character string representing the RIPEMD-160 hash in the specified format.
#'
#' @examples
#' ripemd_160("Hello, world!")
#' ripemd_160(charToRaw("Hello, world!"), output_format = "base64")
#'
#' @import openssl
#' @import sodium
#' @export
ripemd_160 <- function(x, output_format = "hex", input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it is a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the RIPEMD-160 hash
  hash_raw <- openssl::ripemd160(x)

  # Convert the hash to the desired output format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else {
    stop("Unsupported output format. Use 'hex' or 'base64'.")
  }
}
