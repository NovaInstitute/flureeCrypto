
#' Validate private key
#' 
#' @description
#' This wrapper function calls its corresponding C function which 
#' checks if a provided private key is valid on the secp256k1 curve.
#' A valid private key must be a 256-bit (32-byte) number within the valid range.
#' 
#' @param private_key_hex A string representing the private key in hexadecimal format.
#' 
#' @return An integer (1 if valid, 0 otherwise).
#' 
#' @examples
#' \dontrun{
#' if (valid_private("6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")) {
#'   print("Private key is valid")
#' }
#' }
#' 
valid_private <- function(private_key_hex) {
  result <- .Call("valid_private_R", private_key_hex)
  return(result)
}

#' Generate private key
#' 
#' @description
#' This wrapper function calls its corresponding C function which generates a 
#' random 32-byte private key that is valid on the secp256k1 curve.
#' The key is cryptographically secure and suitable for signing operations.
#' 
#' @param output_format The format of the output. Options are "hex" (default), "base64", or "raw".
#' 
#' @return A 32-byte private key in the specified format.
#' 
#' @examples
#' \dontrun{
#' # Generate a new random private key in hex format
#' new_random_key <- generate_seckey(output_format = "hex")
#' }
#' 
#' @importFrom base64enc base64encode
#' 
generate_seckey <- function(output_format = c("hex", "base64", "raw")[1]) {
  privkey <- .Call("generate_seckey_R")
  
  if (output_format == "hex") {
    return(bin2hex(privkey))
  } else if (output_format == "base64") {
    return(base64encode(privkey))
  } else if (output_format == "raw") {
    return(privkey)
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

#' Generate a key pair
#' 
#' @description
#' Generates a secp256k1 key pair by calling on the corresponding C function. 
#' If a private key is provided, the function generates
#' the corresponding public key. 
#' If no private key is provided, it generates a new key pair.
#' 
#' @param priv_key Optional raw vector or hex string representing the 32-byte private key.
#' 
#' @return A list with:
#'   - `privkey`: A hexadecimal string representing the 32-byte private key.
#'   - `pubkey`: A hexadecimal string representing the 32-byte compressed public key.
#' 
#' @examples
#' # new_kp <- generate_keypair()
#' # generated_private_key <- new_kp[[1]]
#' # generated_public_key <- new_kp[[2]]
#' 
#' # new_kp_given_private_key <- generate_keypair("6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")
#' 
#' @importFrom base64enc base64encode
#' 
#' @export
generate_keypair <- function(priv_key = NULL, output_format = c("hex", "base64", "raw")[1]) {
  if (is.null(priv_key)) {
    keypair <- .Call("generate_keypair_R")
    privkey = keypair[[1]]
    pubkey = keypair[[2]]
  } else {
    if (is.character(priv_key)) {
      seckey_r = hex2bin(priv_key)
    }
      privkey = seckey_r
      pubkey = .Call("generate_keypair_with_seckey_R", seckey_r)
  }
  
  if (output_format == "hex") {
    privkey = bin2hex(privkey)
    pubkey = bin2hex(pubkey)
    return(list(privkey, pubkey))
  } else if (output_format == "base64") {
    privkey = base64enc::base64encode(privkey)
    pubkey = base64enc::base64encode(pubkey)
    return(list(privkey, pubkey))
  } else if (output_format == "raw") {
    return(list(privkey, pubkey))
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'raw'.")
  }
}

#' Sign a message hash
#' 
#' @description
#' This wrapper function calls on the corresponding C function to sign a 32-byte 
#' message hash using a provided private key. If the provided message is a
#' character string the sha2_256() hash of the message is used for signing.
#' The resulting signature is in DER encoded format prepended by a recovery byte.
#' 
#' @param msg A raw vector containing the 32-byte message hash or the original message as a character string.
#' @param priv_key A raw vector containing the 32-byte private key or the private key as a hexadecimal string.
#' 
#' @return The signature as a hexadecimal string.
#' 
#' @examples
#' # sig <- sign_message("hi", "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2")
#' 
#' @importFrom base64enc base64encode
#' 
#' @export
sign_message <- function(msg, priv_key, output_format = c("hex", "base64", "raw")[1]) {
  if (is.character(msg)) {
    msg_hash <- hex2bin(sha2_256(msg))
  } else if (is.raw(msg)) {
    msg_hash <- msg
  } else {
    stop("The message should be a character string or raw vector.")
  }
  
  if (is.character(priv_key)) {
    priv_key <- hex2bin(priv_key)
  } else if (!is.raw(priv_key)) {
    stop("The private key should be a hexadecimal string or raw vector.")
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

#' Verify a signature from a hash
#'
#' @description
#' Verifies that a signature is valid for a given public key and hash.
#' The signature is assumed to be in DER encoded format prepended by a recovery byte.
#'
#' @param pub_key A character string representing the public key in hexadecimal format.
#' @param message A character string representing the original message.
#' @param signature A character string representing the signature in hexadecimal format.
#'
#' @return TRUE if the signature is valid for the given public key and hash, 
#'   otherwise stops with an error message.
#'
#' @examples
#' # pub_key = "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
#' # message = "hi there"
#' # sig = "1c304402207eb1cbcdaaf623121e97abbf4018200628a7abba796f403edf01a367d908d88302205a790d706c70b9d0f657bf7a4a7b5c04808825ba0ce227bff33a0fdb3eab1ac0"
#' 
#' # verify_signature(pub_key, message, sig)
#'
#' @export
verify_signature <- function(pub_key, message, sig) {
  hash <- hex2bin(sha2_256(message))
  
  # Extract the recovery byte from the signature
  head1 <- substr(sig, 1, 2)
  # Extract the second byte from the signature (which should be '30' for DER encoded signatures)
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


#' Recover public key from a signature
#' 
#' @description
#' Recovers the public key associated with a given ECDSA signature and message hash on the secp256k1 curve.
#' The signature is assumed to be DER encoded with a prepended recovery byte.

#' @param msg A character string or raw vector representing the message hash that was signed.
#' @param sig A string representing the signature in hexadecimal format.
#' 
#' @return A hexadecimal string representing the 32-byte compressed public key if the recovery was successful.
#' 
#' @examples
#' # msg = "hi there"
#' # sig = "1c304402207eb1cbcdaaf623121e97abbf4018200628a7abba796f403edf01a367d908d88302205a790d706c70b9d0f657bf7a4a7b5c04808825ba0ce227bff33a0fdb3eab1ac0"
#' # recovered_public_key <- public_key_from_message(msg, sig)
#' 
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
#' @description
#' This function generates a SIN from a given public key by leveraging the
#' SHA-256 and RIPEMD-160 hash functions, followed by Base58Check encoding.
#' The SIN is used as a unique identifier derived from the public key.
#'
#' @param pub_key A character string (hexadecimal format) or raw vector representing the public key.
#' @param output_format A character string specifying the output format.
#'   Can be "hex" (hexadecimal string), "raw" (raw byte vector), or "base58" (Base58Check encoded string, default).
#'
#' @return The SIN in the specified format. The output will be:
#'   - a hexadecimal string if `output_format` is "hex",
#'   - a raw vector if `output_format` is "raw",
#'   - a Base58Check encoded string if `output_format` is "base58".
#'
#' @examples
#' \dontrun{
#' pub_key_hex <- "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
#' sin <- get_sin_from_public_key(pub_key_hex, output_format = "base58")
#' }
#' 
#' @importFrom rbtc base58CheckEncode
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

#' Derive a public key from a private key
#'
#' This function generates a public key from a given private key by creating a key pair.
#'
#' @param priv_key A raw vector or hexadecimal character string representing the private key. 
#'
#' @return A raw vector representing the public key derived from the private key.
#' 
#' @examples
#' # priv_key = "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
#' # public_key <- public_key_from_private(priv_key)
#'
#' @export
public_key_from_private <- function(priv_key) {
  kp <- generate_keypair(priv_key)
  pub_key <- kp[[2]]
  return(pub_key)
}

#' Generate account ID from a public key
#'
#' @description
#' This function generates an account identifier (SIN) from a given public key.
#'
#' @param pub_key A raw vector or hexadecimal character string representing the public key. 
#'
#' @return A character string representing the account ID in base58 encoded format.
#'
#' @examples
#' # pubkey = "02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"
#' # account_id <- account_id_from_public(pub_key)
#'
#' @export
account_id_from_public <- function(pub_key) {
  return(get_sin_from_public_key(pub_key))
}

#' Generate account ID from a private key
#'
#' @description
#' This function generates an account identifier (SIN) from a given private key by 
#' first deriving the corresponding public key, then creating the account ID.
#'
#' @param priv_key A raw vector or hexadecimal character string representing the private key. 
#'
#' @return A character string representing the account ID in base58 encoded format.
#'
#' @examples
#' # priv_key = "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
#' # account_id <- account_id_from_private(priv_key)
#'
#' @export
account_id_from_private <- function(priv_key) {
  pub_key <- public_key_from_private(priv_key)
  return(get_sin_from_public_key(pub_key))
}

#' Generate account ID from a signature
#'
#' @description
#' This function generates an account identifier (SIN) by recovering the public key 
#' from a message's signature and then deriving the account ID from the recovered key.
#' The signature should be DER encode prepended by the recovery byte.
#'
#' @param hex_signature A character string representing the signature of the message 
#'   in hexadecimal format.
#' @param msg A character string or raw vector representing the original message. 
#'
#' @return A character string representing the account ID derived from the 
#'   recovered public key.
#'
#' @examples
#' # msg = "hi there"
#' # hex_signature = "1b3046022100cbd32e463567fefc2f120425b0224d9d263008911653f50e83953f47cfbef3bc022100fcf81206277aa1b86d2667b4003f44643759b8f4684097efd92d56129cd89ea8"
#' # account_id <- account_id_from_message(hex_signature, msg)
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



