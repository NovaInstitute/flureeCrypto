#' Validate a Private Key for the secp256k1 Curve
#'
#' This function checks whether a given private key is valid for the secp256k1 curve. A valid private key must be a big integer that falls within the range [1, modulus - 1], where modulus is the order of the secp256k1 curve.
#'
#' @param private_key A `bigz` object representing the private key to be validated.
#'
#' @return A logical value (`TRUE` or `FALSE`) indicating whether the private key is valid.
#'
#' @examples
#' # Example private key in hexadecimal
#' private_key <- "0521b34877d71a6c7bba4cc53c5ffdbf5023c3b1fb71f7b1a384330fe6e9986d"
#'
#' # Convert to bigz and validate
#' private_bn <- gmp::as.bigz(paste0("0x", private_key))
#' is_valid <- valid_private_key(private_bn)
#' print(is_valid)  # This should print TRUE if the key is valid
#'
#' @import gmp
#' @export
valid_private_key <- function(private_key) {
  # Ensure private_key is a bigz object
  if (!inherits(private_key, "bigz")) {
    stop("private_key must be a bigz object")
  }

  # Define the secp256k1 curve modulus
  modulus <- gmp::as.bigz("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

  # Check if the private key is between 1 and the modulus
  return(private_key >= 1 && private_key < modulus)
}

