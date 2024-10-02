
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
#' ripemd_160("hi there!", output_format = "hex")
#' ripemd_160(charToRaw("hi there!"), output_format = "hex")
#' # (= "ad6ce46f7f1ea8519dc02ce8ce0c278c6ff329b2" (alphabase/bytes->hex (ripemd-160 (.getBytes "hi there!")))))
#' ripemd_160(charToRaw("hi there!"), output_format = "base64")
#' ripemd_160(charToRaw("hi there!"), output_format = "raw")
#' @import openssl
#' @import sodium
#' @export
ripemd_160 <- function(x, output_format = c("hex", "base64", "raw")[3], input_format = NULL) {

  # Determine the input format if not provided
  if (is.null(input_format)) {
    input_format <- coerce_input_format(x)
  }

  # Convert input to a raw vector if it's a string
  if (input_format == "string") {
    x <- charToRaw(normalize_string(x))
  }

  # Calculate the RIPEMD-160 hash
  hash_raw <- openssl::ripemd160(x)

  # Return in the desired format
  if (output_format == "hex") {
    return(bin2hex(hash_raw))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hash_raw))
  } else if (output_format == "raw") {
    return(hash_raw)  # return raw byte array (similar to the Clojure byte array)
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

