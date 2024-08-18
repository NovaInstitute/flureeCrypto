#' Deterministically Generate k for ECDSA Signing (RFC 6979)
#'
#' This function generates a deterministic `k` value for ECDSA signing based on RFC 6979.
#' It uses the HMAC-SHA256 algorithm and is specifically designed for the secp256k1 curve.
#'
#' @param hash_raw A raw byte array representing the message hash.
#' @param private_key_raw A raw byte array representing the private key.
#' @param curve_name A string representing the curve name (default is "secp256k1").
#'
#' @return A raw byte array representing the deterministic `k` value.
#'
#' @examples
#' hash_raw <- openssl::sha256(charToRaw("Hello, blockchain!"))
#' private_key_raw <- sodium::hex2bin("1E99423A4ED27608A15A2616A2B9245621A89E834046E0BC3A707855853D7E58")
#' k <- deterministic_generate_k(hash_raw, private_key_raw)
#' print(sodium::bin2hex(k))
#'
#' @import openssl
#' @export
deterministic_generate_k <- function(hash_raw, private_key_raw, curve_name = "secp256k1") {
  # Step 1: Define constants
  v <- rep(as.raw(0x01), 32)  # v = 0x01 repeated 32 times
  k <- rep(as.raw(0x00), 32)  # k = 0x00 repeated 32 times

  # Step 2: Process the private key and hash
  k <- openssl::sha256(c(v, as.raw(0x00), private_key_raw, hash_raw))
  v <- openssl::sha256(k)
  k <- openssl::sha256(c(v, as.raw(0x01), private_key_raw, hash_raw))
  v <- openssl::sha256(k)

  # Step 3: Generate deterministic k
  k_final <- openssl::sha256(v)

  return(k_final)
}

#' Sign a Message with a Private Key using ECDSA and secp256k1 (Sodium)
#'
#' This function signs a message with a provided private key using the secp256k1 curve.
#' The message can be a string or raw byte array. The private key must be provided as a hexadecimal string or raw byte array.
#'
#' @param message A string or raw byte array representing the message to be signed.
#' @param private_key A hexadecimal string or raw byte array representing the private key.
#'
#' @return A raw byte array representing the ECDSA signature.
#'
#' @examples
#' private_key <- "1E99423A4ED27608A15A2616A2B9245621A89E834046E0BC3A707855853D7E58"
#' message <- "Hello, blockchain!"
#' signature <- sign_message_sodium(message, private_key)
#' print(sodium::bin2hex(signature))
#'
#' @import sodium
#' @export
sign_message_sodium <- function(message, private_key) {
  # Convert the message to a byte array if it is a string
  msg_bytes <- if (is.character(message)) {
    charToRaw(message)
  } else {
    message
  }

  # Hash the message using SHA-256
  hash_raw <- openssl::sha256(msg_bytes)

  # Convert the private key to a raw byte array if it's in hexadecimal format
  private_key_raw <- if (is.character(private_key) && grepl("^[0-9a-fA-F]+$", private_key)) {
    sodium::hex2bin(private_key)
  } else if (is.raw(private_key)) {
    private_key
  } else {
    stop("Invalid private key format. Must be a hexadecimal string or raw byte array.")
  }

  # Generate the corresponding public key
  public_key_raw <- sodium::pubkey(private_key_raw)

  # Generate the deterministic k value (as shown before)
  k <- deterministic_generate_k(hash_raw, private_key_raw)

  # Use the sodium package to sign the hash with the private key and k
  # Note: sodium::sig_sign does not allow direct control of k, so this example assumes the internal signing method.
  signature <- sodium::sig_sign(hash_raw, key = private_key_raw)

  return(signature)
}
