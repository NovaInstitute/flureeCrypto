#' Generate a secp256k1 Keypair
#'
#' This function generates a secp256k1 keypair. If a private key (`seckey`) is provided,
#' the public key is generated from the private key. If no `seckey` is provided, a random
#' private key is generated.
#'
#' @param seckey Optional 32-byte raw vector representing a private key. If `NULL`, a random
#' private key will be generated.
#'
#' @return A list with two elements:
#' \describe{
#'   \item{private}{A hexadecimal string representing the private key.}
#'   \item{public}{A hexadecimal string representing the public key.}
#' }
#'
#' @examples
#' # Generate a random keypair
#' keypair <- generate_keypair_wrapper()
#' print(keypair)
#'
#' # Generate a keypair from a provided private key
#' seckey <- as.raw(sample(0:255, 32, replace = TRUE))
#' keypair <- generate_keypair_wrapper(seckey)
#' print(keypair)
#'
#' @export
generate_keypair <- function(seckey = NULL) {
  if (is.null(seckey)) {
    # Call the C function that generates a random keypair
    keypair <- .Call("generate_keypair_R")
  } else {
    # Validate the provided seckey (should be a 32-byte raw vector)
    if (!is.raw(seckey) || length(seckey) != 32) {
      stop("Invalid private key: must be a 32-byte raw vector")
    }
    
    # Call the C function with the provided seckey
    keypair <- .Call("generate_keypair_with_seckey_R", seckey)
  }
  
  # Extract and return the private and public keys in hex format
  private_key <- bin2hex(keypair[[1]])  # Convert private key to hex
  public_key <- bin2hex(keypair[[2]])   # Convert public key to hex
  
  list(private = private_key, public = public_key)
}

#' Sign a message hash
#' @param seckey Private key (32 bytes)
#' @param hash Message hash (32 bytes)
#' @return A raw vector of the signature (64 bytes)
#' @export
sign_hash <- function(message, seckey) {
  hash <- hex2bin(sha2_256(message))
  if (is.character(hash)) {
    hash <- charToRaw(hash)
  }
  if (!is.raw(seckey)) {
    seckey = hex2bin(seckey)
  }
  stopifnot(is.raw(seckey) && length(seckey) == 32)
  stopifnot(is.raw(hash) && length(hash) == 32)
  
  signature <- .Call("sign_hash_R", seckey, hash)
  return(bin2hex(signature))
}

#' Sign a message using ECDSA with secp256k1
#'
#' This function hashes the input message using SHA-256 and signs the resulting hash using the provided private key.
#' The signing process uses the secp256k1 curve via the `libsecp256k1` C library.
#'
#' @param message A character string or raw vector representing the message to be signed.
#' @param private_key A private key used for signing, given either as a hex-encoded string or a raw vector.
#' @return A hex-encoded string representing the DER-encoded ECDSA signature.
#' @details
#' The function first hashes the message using SHA-256, then signs the hash with the provided private key using 
#' the secp256k1 curve. It can optionally generate a recovery byte as part of the signature.
#'
#' @examples
#' # Sign a message with a hex-encoded private key
#' message <- "Hello, World!"
#' private_key <- "1e99423a4ed27608a15a2616a2b7c778943e87158c9993bbbd4a889eeaf63bfc"
#' signature <- sign(message, private_key)
#' cat("Signature:", signature, "\n")
#'
#' @import digest
#' @export
sign <- function(message, private_key) {
  # Hash the message using SHA-256
  hash <- sha2_256(message)
  
  # Convert private key from hex to raw bytes if necessary
  if (is.character(private_key)) {
    private_key <- as.raw(as.hexmode(private_key))
  }
  
  # Call the sign_hash function to get the signature
  signature <- sign_hash(hash, private_key, recovery_byte = TRUE)
  
  return(signature)
}

#' Check if private key is valid
#' @param seckey Private key (32 bytes)
#' @return TRUE if the private key is valid, FALSE otherwise
#' @export
is_valid_private_key <- function(seckey) {
  if (!is.raw(seckey)) {
    seckey = hex2bin(seckey)
  }
  stopifnot(is.raw(seckey) && length(seckey) == 32)
  .Call("is_valid_private_key_R", seckey)
}