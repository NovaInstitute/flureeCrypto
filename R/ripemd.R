
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
#'
#' @export
ripemd_160 <- function(ba, output_format = "hex") {
  # Calculate the RIPEMD-160 hash
  hash_raw <- openssl::ripemd160(ba)

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
