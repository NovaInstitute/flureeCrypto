#' RIPEMD-160 Hashing Function
#'
#' This function calculates the RIPEMD-160 hash of the input byte array.
#'
#' @param x A raw vector or character string representing the byte array to be hashed.
#'
#' @return A raw vector representing the RIPEMD-160 hash is the specified output format.
#' @import openssl
#' @examples
#' hash_ripemd160 <- ripemd_160("hi there!")
#'
#' @export
ripemd_160 <- function(x, output_format = "hex") {
  if (is.character(x)) {
    ba <- charToRaw(x)
  } else {
    ba <- x
  }
  
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
