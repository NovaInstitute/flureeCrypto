#' Generate Public Key from Private Key for the secp256k1 Curve
#'
#' This function takes a private key (in hex string or big integer format) and returns the corresponding public key as a hex string.
#'
#' @param private_key A hexadecimal string or big integer (bigz) representing the private key.
#'
#' @return A hexadecimal string representing the public key.
#'
#' @examples
#' private_key <- create_valid_secp256k1_private_key()
#' public_key <- pub_key_from_private(private_key)
#' print(public_key)
#'
#' @import gmp
#' @export
pub_key_from_private <- function(private_key) {
  # Use the existing public_key_from_private function to get the key pair
  key_pair <- keypair_from_private(private_key)

  # Return the public key (hexadecimal string)
  return(key_pair$public)
}

