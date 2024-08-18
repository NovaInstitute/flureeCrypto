#' @title get_sin_from_public_key
#' @description
#' Generate SIN from public key
#' @param pub_key_hex Character. The public key in hexadecimal format.
#' @param output_format Character. The output format for the SIN. Default is "base58".
#' @import openssl
#' @import rbtc
#' @return character
#' @examples
#' pub_key_hex <- "031fbbad2f558783b4490692f46fff26a10fc7c3633741cb450f104d598320a6d6"
#' sin <- get_sin_from_public_key(pub_key_hex)

get_sin_from_public_key <- function(pub_key_hex, output_format = "base58") {
  # Step 1: Convert public key to raw bytes
  pub_key_raw <- sodium::hex2bin(pub_key_hex)

  # Step 2: Hash the public key using SHA-256
  sha256_hash <- openssl::sha256(pub_key_raw)

  # Step 3: Hash the result using RIPEMD-160
  ripemd160_hash <- openssl::ripemd160(sha256_hash)

  # Step 4: Prepend version bytes 0x0F and 0x02
  version_prefix <- as.raw(c(0x0F, 0x02))
  prefixed_hash <- c(version_prefix, ripemd160_hash)

  # Step 5: Calculate the checksum (double SHA-256 and take first 4 bytes)
  checksum <- openssl::sha256(openssl::sha256(prefixed_hash))
  checksum <- checksum[1:4]

  # Step 6: Combine the prefixed hash and checksum
  final_bytes <- c(prefixed_hash, checksum)

  # Step 7: Encode the final bytes using Base58
  if (output_format == "base58") {
    sin <- rbtc:::base58CheckEncode(final_bytes)
  } else {
    sin <- final_bytes  # Alternative encoding can be implemented if needed
  }

  return(sin)
}

#' get_sin_from_private_key
#' @description
#' Derive public key from private key and generate SIN
#' @param private_key_hex Character. The private key in hexadecimal format.
#' @param output_format Character. The output format for the SIN. Default is "base58".
#' @return Character SIN
#' @export
#'
#' @examples
#' private_key_hex <- "1E99423A4ED27608A15A2616A2B9245621A89E834046E0BC3A707855853D7E58"
#' sin <- get_sin_from_private_key(private_key_hex)

get_sin_from_private_key <- function(private_key_hex, output_format = "base58") {
  # Convert the private key from hex to raw bytes
  private_key_raw <- hex_to_raw(private_key_hex)

  # Generate the public key using the sodium package
  public_key_raw <- sodium::pubkey(private_key_raw)

  # Convert the public key to a hexadecimal string
  pub_key_hex <- format_public_key(paste0(sprintf("%02x", as.integer(public_key_raw)), collapse = ""))

  # Use the public key to generate the SIN
  sin <- get_sin_from_public_key(pub_key_hex, output_format)

  return(sin)
}


#' hex_to_raw
#' @description
#' Convert hexadecimal string to raw bytes
#' @param hex Character. Hexadecimal string to convert to raw bytes.
#'
#' @return raw
#' @export
#'
#' @examples
#' hex <- "031fbbad2f558783b4490692f46fff26a10fc7c3633741cb450f104d598320a6d6"
#' raw_bytes <- hex_to_raw(hex)

hex_to_raw <- function(hex) {
  raw_vec <- as.raw(strtoi(substring(hex, seq(1, nchar(hex), by = 2), seq(2, nchar(hex), by = 2)), 16L))
  return(raw_vec)
}
