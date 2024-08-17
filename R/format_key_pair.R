#' Format a Key Pair for the secp256k1 Curve
#'
#' This function takes a key pair and returns the X9.62 compressed encoded public key and private key as a list, with each value hex-encoded.
#'
#' @param private_key A raw vector, hexadecimal string, or big integer (bigz) representing the private key.
#' @param public_key A hexadecimal string representing the public key.
#' @param compressed Logical, whether to return the public key in compressed format (default: `TRUE`).
#'
#' @return A list containing the hex-encoded private key and the formatted public key.
#'
#' @examples
#' # Generate a private key using rbtc
#' private_key <- create_secp256k1_private_key()
#'
#' # Generate the corresponding public key
#' public_key <- PrivKey2PubKey(private_key)
#'
#' # Format the key pair
#' key_pair <- format_key_pair(private_key, public_key)
#' print(key_pair$private)
#' print(key_pair$public)
#'
#' @import rbtc
#' @import gmp
#' @import sodium
#' @export
format_key_pair <- function(private_key, public_key, compressed = TRUE) {
  # Convert private key to hexadecimal if it's not already
  if (is.raw(private_key)) {
    # If the private key is a raw vector, convert it to hex
    private_hex <- sodium::bin2hex(private_key)
  } else if (inherits(private_key, "bigz")) {
    # If the private key is a big integer, convert it to a hexadecimal string
    private_hex <- as.character(private_key, base = 16)
  } else if (is.character(private_key) && grepl("^[0-9a-fA-F]+$", private_key)) {
    # If the private key is already a hexadecimal string, use it as is
    private_hex <- private_key
  } else {
    stop("Invalid private key format. Must be a raw vector, bigz object, or hexadecimal string.")
  }

  # Pad the private key to 64 characters (32 bytes)
  private_hex <- sprintf("%064s", private_hex)

  # Format the public key using the previously defined function
  formatted_public_key <- format_public_key(public_key, compressed = compressed)

  # Return the key pair as a list with hex-encoded private and public keys
  return(list(
    private = private_hex,
    public = formatted_public_key
  ))
}
