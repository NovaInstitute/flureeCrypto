#rbtc approach

# Generate a private key using rbtc
generate_secp256k1_private_key <- function() {
  private_key <- rbtc::createPrivateKey()
  return(private_key)
}

# Derive the public key from the private key using rbtc
derive_public_key <- function(private_key) {
  public_key <- rbtc::PrivKey2PubKey(private_key)
  return(public_key)
}

#' Sign a Message with a Private Key using ECDSA and secp256k1 (rbtc)
#'
#' This function signs a message with a provided private key using the secp256k1 curve.
#' The message can be a string or raw byte array. The private key must be provided as a hexadecimal string.
#'
#' @param message A string or raw byte array representing the message to be signed.
#' @param private_key A hexadecimal string representing the private key.
#'
#' @return A hexadecimal string representing the ECDSA signature.
#'
#' @examples
#' private_key <- generate_secp256k1_private_key()
#' message <- "Hello, blockchain!"
#' signature <- sign_message_rbtc(message, private_key)
#' print(signature)
#'
#' @import rbtc
#' @export
sign_message_rbtc <- function(message, private_key) {
  # Convert the message to a byte array if it is a string
  msg_bytes <- if (is.character(message)) {
    charToRaw(message)
  } else {
    message
  }

  # Hash the message using SHA-256
  hash_raw <- openssl::sha256(msg_bytes)

  # Generate the deterministic k value (as shown before)
  k <- deterministic_generate_k(hash_raw, sodium::hex2bin(private_key))

  # Sign the hash using rbtc (assuming a function exists, otherwise manual calculation needed)
  signature <- rbtc::signMessage(hash_raw, private_key) # Replace with actual function or implement manually

  return(signature)
}
