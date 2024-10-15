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

#' @title Deterministic Generation of k
#' @description Deterministically generate a random number in accordance with RFC 6979. 
#' Provided hash should have 256 bits to align with the secp256k1 curve.
#' @param hash_ba A raw vector representing the hash (should be 32 bytes).
#' @param priv_key A raw vector representing the private key.
#' @return A big integer representing the generated k value.
#' @export
deterministic_generate_k <- function(hash_ba, priv_key) {
  # Get the curve order bytes from the C function
  order_bytes <- .Call("get_curve_order")  # Call the existing C function
  
  # Assert that hash length matches curve byte length
  curve_bytes <- length(order_bytes)  # Should be 32 bytes for secp256k1
  if (length(hash_ba) != curve_bytes) {
    stop("Hash should have the same number of bytes as the curve.")
  }
  
  # Initialize variables
  v <- as.raw(rep(0x01, curve_bytes))
  k <- as.raw(rep(0x00, curve_bytes))
  pk <- as.raw(priv_key)  # Convert private key to raw
  left_padding <- as.raw(rep(0, curve_bytes - length(hash_ba)))
  hash <- c(left_padding, hash_ba)
  
  # Generate k using HMAC
  k <- hmac_sha256(c(v, as.raw(0), pk, hash), k)
  v <- hmac_sha256(v, k)
  k <- hmac_sha256(c(v, as.raw(1), pk, hash), k)
  v <- hmac_sha256(v, k)
  
  # Final k generation and assertion
  result <- hmac_sha256(v, k)
  
  if (length(result) != curve_bytes) {
    stop("Hash should have the same number of bytes as the curve modulus.")
  }
  
  # Convert the result from raw to big integer (assuming a function to handle this)
  return(rawToBigInteger(result))
}

#' @title Convert Raw to Big Integer
#' @description Convert a raw vector to a big integer.
#' @param raw_data A raw vector to be converted.
#' @return A big integer representation of the raw vector.
rawToBigInteger <- function(raw_data) {
  # Convert raw data to character string and then to a big integer
  return(as.integer(paste0("0x", paste(as.hexmode(raw_data), collapse = ""))))
}

#' Get the Curve Order
#'
#' Retrieves the curve order from the secp256k1 elliptic curve.
#' 
#' @return A raw vector representing the curve order.
#' @export
get_modulus <- function() {
  N <- .Call("get_modulus_R")
  return(N)
}
# this function works... implement hex->biginteger for conversion


#' Compute Recovery Byte
#'
#' Compute a recovery byte for a compressed ECDSA signature given R and S parameters.
#' Returns the value as a byte integer.
#'
#' @param kp An object representing the elliptic curve point.
#' @param r A numeric representing the R parameter of the ECDSA signature.
#' @param s A numeric representing the S parameter of the ECDSA signature.
#' @return An integer representing the recovery byte.
#' @export
compute_recovery_byte <- function(kp, r, s) {
  # Retrieve the curve order from the C function
  order_raw <- get_curve_order()
  
  # Convert the raw vector to an integer
  n <- as.numeric(order_raw)
  
  # Check if r and s are valid
  big_r <- r >= n
  big_s <- (s + s) >= n
  
  # Determine if y-coordinate of kp is odd
  y_odd <- isTRUE(kp$y %% 2 == 1)  # Assuming kp has an element `y`
  
  # Compute recovery byte
  recovery_byte <- 0x1B +
    (if (!big_s == y_odd) 1 else 0) +
    (if (big_r) 2 else 0)
  
  return(recovery_byte)
}

#' Sign a Hash
#'
#' Returns a signature for the given hash using the provided private key.
#' Utilizes deterministic generation of k according to RFC 6979.
#'
#' @param hash_ba A raw vector representing the hash to be signed.
#' @param private_bn A numeric representing the private key.
#' @param recovery_byte Logical indicating whether to compute the recovery byte.
#' @return A character string representing the hexadecimal encoded DER signature.
#' @export
sign_hash <- function(hash_ba, private_bn, recovery_byte = TRUE) {
  # Generate k deterministically
  k <- deterministic_generate_k(hash_ba, private_bn)
  
  # Retrieve curve order
  order_bytes <- .Call("get_curve_order")  # Call to get curve order in bytes
  n <- rawToBigInteger(order_bytes)  # Convert raw bytes to big integer
  
  # Convert hash to big integer
  z <- as.numeric(hash_ba)
  
  # Compute the elliptic curve point using C function
  kp <- .Call("ec_multiply_generator", k)  # Call C function to multiply G by k
  
  # Extract R and S values from the elliptic curve point
  r <- as.numeric(kp[1]) %% n
  s_ <- (k^(-1) * (r * private_bn + z)) %% n
  s <- ifelse((s_ + s) < n, s_, (n - s_))
  
  # Compute recovery byte if requested
  recovery_byte_value <- if (recovery_byte) {
    compute_recovery_byte(kp, r, s_)
  } else {
    NULL
  }
  
  # DER encode the signature
  der_sig <- der_encode_ecdsa_signature(r, s, recovery_byte_value)
  
  # Convert the signature to hexadecimal format
  hex_signature <- bytes_to_hex(der_sig)
  
  return(hex_signature)
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
  
  if (is.character(message)) {
    message <- charToRaw(message)
  }
  
  # Hash the message using SHA-256
  hash <- sha2_256(message)
  
  # Convert private key from hex to raw bytes if necessary
  if (is.character(private_key)) {
    private_key <- hex_to_biginteger(private_key)
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