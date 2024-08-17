
#' Format a Public Key for the secp256k1 Curve
#'
#' This function formats the internal representation of a public key to a standard public key format used in the secp256k1 curve.
#'
#' @param public_key A hexadecimal string representing the public key.
#' @param compressed Logical, whether to return the public key in compressed format (default: `TRUE`).
#'
#' @return A hexadecimal string containing the formatted public key.
#'
#' @examples
#' private_key <- createPrivateKey()
#' public_key <- PrivKey2PubKey(private_key)
#' formatted_key <- format_public_key(public_key)
#'
#' @import rbtc
#' @export
format_public_key <- function(public_key, compressed = TRUE) {
  # Convert the hex public key to raw bytes using decodeHex
  pubkey_raw <- decodeHex(public_key)

  if (compressed) {
    # Extract the X and Y coordinates
    x <- pubkey_raw[2:33]
    y <- pubkey_raw[34:65]

    # Determine the prefix based on the parity of Y (0x02 for even, 0x03 for odd)
    prefix <- ifelse(as.integer(y[length(y)]) %% 2 == 0, 0x02, 0x03)

    # Construct the compressed public key
    compressed_key <- c(as.raw(prefix), x)

    # Convert the compressed key to a hexadecimal string
    return(sodium::bin2hex(compressed_key))
  } else {
    # Uncompressed format, simply return as it is
    return(public_key)
  }
}

