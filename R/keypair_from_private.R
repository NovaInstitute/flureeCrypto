#' Generate Public Key from Private Key for the secp256k1 Curve
#'
#' This function generates a public key from a given private key using the secp256k1 curve.
#'
#' @param private_key A hexadecimal string or big integer (bigz) representing the private key.
#'
#' @return A list containing the big integer private key and the corresponding public key as a hexadecimal string.
#'
#' @examples
#' private_key <- create_valid_secp256k1_private_key()
#' key_pair <- keypair_from_private(private_key)
#' print(key_pair$private)
#' print(key_pair$public)
#'
#' @import rbtc
#' @import gmp
#' @export
keypair_from_private <- function(private_key) {
  # Convert the private key to a big integer if it's not already
  if (is.character(private_key) && grepl("^[0-9a-fA-F]+$", private_key)) {
    # Convert hexadecimal string to big integer
    private_bn <- gmp::as.bigz(paste0("0x", private_key))
  } else if (inherits(private_key, "bigz")) {
    # If it's already a big integer, use it directly
    private_bn <- private_key
  } else {
    stop("Invalid private key format. Must be a hexadecimal string or bigz object.")
  }

  # Validate the private key
  if (!valid_private_key(private_bn)) {
    stop("Invalid private key. Must be a big integer and >= 1, <= curve modulus.")
  }

  # Generate the public key using secp256k1
  public_key <- rbtc::PrivKey2PubKey(as.character(private_bn, base = 16))

  # Return the key pair as a list with the big integer private key and the public key as a hexadecimal string
  return(list(
    private = private_bn,
    public = public_key
  ))
}
