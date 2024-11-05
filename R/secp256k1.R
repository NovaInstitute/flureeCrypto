
#' Validate Private Key
#' 
#' Checks if a provided private key (hexadecimal string) is valid on the secp256k1 curve.
#' 
#' @param private_key_hex A string representing the private key in hexadecimal format.
#' @return An integer scalar (1 if valid, 0 otherwise).
#' @export
valid_private <- function(private_key_hex) {
  .Call("valid_private_R", private_key_hex)
}

#' Generate Secret Key
#' 
#' Generates a random 32-byte secret key that is valid on the secp256k1 curve.
#' 
#' @return A raw vector containing the 32-byte secret key.
#' @export
generate_seckey <- function(output_format = c("hex", "base64", "raw")[1]) {
  seckey <- .Call("generate_seckey_R")
  
  if (output_format == "hex") {
    return(bin2hex(seckey))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(seckey))
  } else if (output_format == "raw") {
    return(seckey)
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

#' Generate Key Pair
#' 
#' Generates a secp256k1 key pair. If a secret key is provided, the function generates
#' the corresponding public key. If no secret key is provided, it generates a new key pair.
#' 
#' @param seckey_r Optional. A raw vector containing the 32-byte secret key.
#' 
#' @return A list with:
#'   - `seckey`: A raw vector containing the 32-byte secret key (only if no key was provided).
#'   - `pubkey`: A raw vector containing the 65-byte uncompressed public key.
#' @export
generate_keypair <- function(seckey_r = NULL, output_format = c("hex", "base64", "raw")[1]) {
  if (is.null(seckey_r)) {
    keypair <- .Call("generate_keypair_R")
    seckey = keypair[[1]]
    pubkey = keypair[[2]]
  } else {
    if (is.character(seckey_r)) {
      seckey_r = hex2bin(seckey_r)
    }
      seckey = seckey_r
      pubkey = .Call("generate_keypair_with_seckey_R", seckey_r)
  }
  if (output_format == "hex") {
    seckey = bin2hex(seckey)
    pubkey = bin2hex(pubkey)
    return(list(seckey, pubkey))
  } else if (output_format == "base64") {
    seckey = base64enc::base64encode(seckey)
    pubkey = base64enc::base64encode(pubkey)
    return(list(seckey, pubkey))
  } else if (output_format == "raw") {
    return(list(seckey, pubkey))
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

#' Sign Message Hash
#' 
#' Signs a 32-byte message hash using a provided private key on the secp256k1 curve.
#' 
#' @param msg_hash_r A raw vector containing the 32-byte message hash.
#' @param priv_key_r A raw vector containing the 32-byte private key.
#' @return A list with two elements:
#'   - signature: A raw vector containing the DER-encoded signature.
#'   - recovery_id: An integer scalar representing the recovery ID for signature recovery.
#'   
#' @export
sign <- function(message, priv_key, output_format = c("hex", "base64", "raw")[1]) {
  if (is.character(message)) {
    msg_hash <- hex2bin(sha2_256(message))
  }
  
  if (is.character(priv_key)) {
    priv_key <- hex2bin(priv_key)
  }
  
  signature <- .Call("sign_R_R", msg_hash, priv_key)
  
  if (output_format == "hex") {
    return(bin2hex(signature))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(signature))
  } else if (output_format == "raw") {
    return(signature)
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

#' Verify a Signature from a Hash
#'
#' Verifies that a signature is valid for a given public key and hash.
#'
#' @param pub_key A character string representing the public key in hexadecimal format.
#' @param message A character string representing the original message.
#' @param signature A character string representing the signature in hexadecimal format, 
#'   assumed to be DER-encoded with a recovery byte.
#'
#' @return TRUE if the signature is valid for the given public key and hash, 
#'   otherwise throws an error.
#'
#' @examples
#' # Example usage:
#' # verify(pub_key, message, sig)
#'
#' @export
verify_signature <- function(pub_key, message, sig) {
  hash <- hex2bin(sha2_256(message))
  
  head1 <- substr(sig, 1, 2)
  head2 <- substr(sig, 3, 4)

  recovery_bytes <- c("1b", "1c", "1d", "1e")
  
  if (head1 %in% recovery_bytes && head2 == "30") {
    recovered_pub_key <- public_key_from_message(hash, sig)
    if (identical(pub_key, recovered_pub_key)) {
      return(TRUE)
    } else {
      stop("Verification failed: Public key does not match the recovered key.")
    }
  } else {
    stop("Unknown signature header format.", call. = FALSE)
  }
}


#' Recover Public Key from Signature
#' 
#' Recovers the public key associated with a given ECDSA signature and message hash on the secp256k1 curve.

#' @param msg A character string or raw vector representing the message hash that was signed.
#' @param sig A string representing the ECDSA signature in hexadecimal format, including the recovery byte.
#' 
#' @return A raw vector containing the 65-byte compressed public key if the recovery is successful.
#' @export
public_key_from_message <- function(msg, sig) {
  if (is.character(msg)) {
    hash <- hex2bin(sha2_256(msg))
  } else {
    hash <- msg
  }
  recovered <- .Call("ecrecover_R", sig, hash)
  return(bin2hex(recovered))
}


#' Generate a SIN (Secure Identity Number) from a public key
#'
#' This function generates a SIN from a given public key by applying
#' SHA-256 and RIPEMD-160 hash functions, appending version bytes, and adding a checksum.
#'
#' @param pub_key A character string or raw vector representing the public key.
#'   If a character string, it should be in hexadecimal format and will be converted to raw.
#' @param output_format A character string specifying the output format.
#'   Can be "hex" (hexadecimal string), "raw" (raw byte vector), or "base58" (Base58Check encoded string).
#'   Default is "base58".
#'
#' @return The SIN in the specified format. The output will be:
#'   - a hexadecimal string if `output_format` is "hex",
#'   - a raw vector if `output_format` is "raw",
#'   - a Base58Check encoded string if `output_format` is "base58".
#'
#' @examples
#' # Example usage with a hexadecimal public key
#' pub_key_hex <- "04bfcab45a58b09f12a87f6a736c19a65a..."
#' get_sin_from_public_key(pub_key_hex, output_format = "base58")
#'
get_sin_from_public_key <- function(pub_key, output_format = "base58") {
  if (is.character(pub_key)) {
    pub_key <- hex2bin(pub_key)
  }
  hash <- hex2bin(sha2_256(pub_key))
  hash <- hex2bin(ripemd_160(hash))
  version_bytes <- as.raw(c(0x0F, 0x02))
  prefixed_hash <- c(version_bytes, hash)
  check_sum <- hex2bin(sha2_256(hex2bin(sha2_256(prefixed_hash))))
  
  check_sum <- check_sum[1:4]
  
  result <- c(prefixed_hash, check_sum)
  
  if (output_format == "hex") {
    result_hex <- bin2hex(result)
    return(result_hex)
    
  } else if (output_format == "raw") {
    return(result)
    
  } else if (output_format == "base58") {
    result_base58 <- rbtc::base58CheckEncode(bin2hex(result))
    return(result_base58)
    
  } else {
    stop("Unsupported output format. Use 'hex', 'raw', or 'base58'.")
  }
}

#' Derive Public Key from Private Key
#'
#' This function generates a public key from a given private key by creating a key pair.
#'
#' @param priv_key A raw vector or character string representing the private key. 
#'   This private key will be used to derive the corresponding public key.
#'
#' @return A raw vector representing the public key derived from the private key.
#' 
#' @examples
#' # Example usage:
#' # Assuming `priv_key` is your private key in raw or hex format
#' public_key <- public_key_from_private(priv_key)
#'
#' @export
public_key_from_private <- function(priv_key) {
  kp <- generate_keypair(priv_key)
  pub_key <- kp[[2]]
  return(pub_key)
}

#' Generate Account ID from Public Key
#'
#' This function generates an account identifier (SIN) from a given public key.
#'
#' @param pub_key A raw vector or character string representing the public key. 
#'   This public key will be used to derive the account ID.
#'
#' @return A character string representing the account ID in the specified format 
#'   (typically base58).
#'
#' @examples
#' # Example usage:
#' # Assuming `pub_key` is your public key in raw or hex format
#' account_id <- account_id_from_public(pub_key)
#'
#' @export
account_id_from_public <- function(pub_key) {
  return(get_sin_from_public_key(pub_key))
}

#' Generate Account ID from Private Key
#'
#' This function generates an account identifier (SIN) from a given private key by 
#' first deriving the corresponding public key, then creating the account ID.
#'
#' @param priv_key A raw vector or character string representing the private key. 
#'   This private key will be used to derive the account ID.
#'
#' @return A character string representing the account ID in the specified format 
#'   (typically base58).
#'
#' @examples
#' # Example usage:
#' # Assuming `priv_key` is your private key in raw or hex format
#' account_id <- account_id_from_private(priv_key)
#'
#' @export
account_id_from_private <- function(priv_key) {
  pub_key <- public_key_from_private(priv_key)
  return(get_sin_from_public_key(pub_key))
}

#' Generate Account ID from Message Signature
#'
#' This function generates an account identifier (SIN) by recovering the public key 
#' from a message's signature and then deriving the account ID from the recovered key.
#'
#' @param hex_signature A character string representing the signature of the message 
#'   in hexadecimal format.
#' @param msg A character string or raw vector representing the original message. 
#'   If a character string is provided, it will be hashed to produce a suitable 
#'   key for recovery.
#'
#' @return A character string representing the account ID derived from the 
#'   recovered public key.
#'
#' @examples
#' # Example usage:
#' # Assuming `hex_signature` is the hexadecimal signature of `msg`
#' account_id <- account_id_from_message(hex_signature, msg)
#'
#' @export
account_id_from_message <- function(msg, sig) {
  if (is.character(msg)) {
    hash <- hex2bin(sha2_256(msg))
  } else {
    hash <- msg
  }
  recovered_public <- .Call("ecrecover_R", sig, hash)
  acc_id <- account_id_from_public(recovered_public)
  return(acc_id)
}



