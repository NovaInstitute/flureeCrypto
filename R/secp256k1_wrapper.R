#' Generate a keypair
#' @return A list with 'seckey' and 'pubkey' raw vectors
#' @export
generate_keypair <- function() {
  keypair <- .Call("generate_keypair_R")
  
  seckey_hex <- bin2hex(keypair[[1]])
  pubkey_hex <- bin2hex(keypair[[2]])

  print(seckey_hex)
  print(pubkey_hex)
  
  return(list(private = seckey_hex, public = pubkey_hex))
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