
#' Base64 URL encode function
#'
#' This function encodes a given string into Base64 URL format and removes any trailing '=' padding.
#' It is useful for encoding data in a URL-safe way without padding characters.
#'
#' @param input_string A string to be encoded.
#' @return A Base64 URL encoded string without padding.
#' @examples
#' b64("example string")
b64 <- function(input_string) {
  b64_string <- base64enc::base64encode(charToRaw(input_string))  # Base64 encoding
  gsub("=+$", "", b64_string)                          # Remove trailing '=' padding
}

#' Sign a message using secp256k1 private key
#'
#' This function signs the provided input using a secp256k1 private key and SHA-256 hash algorithm.
#'
#' @param signing_input The message to be signed as a raw vector or string.
#' @param signing_key The secp256k1 private key used for signing.
#' @return A signature as a raw vector.
#' @examples
#' sign("message to sign", my_signing_key)
sign <- function(signing_input, signing_key) {
  signature <- signature_create(charToRaw(signing_input), signing_key, hash = "sha256")
  return(signature)
}

#' Create JWS Compact Serialization
#'
#' This function generates a JWS (JSON Web Signature) Compact Serialization from the provided payload
#' and secp256k1 signing key. It first encodes the JOSE header and payload using Base64 URL encoding,
#' then signs the message and constructs the JWS string.
#'
#' @param payload The payload to be included in the JWS.
#' @param signing_key The secp256k1 signing key used to sign the payload.
#' @return A JWS compact serialization as a string.
#' @examples
#' serialize_jws("example payload", my_signing_key)
serialize_jws <- function(payload, signing_key) {
  # JOSE header
  JOSE_header <- "{\"alg\":\"ES256K-R\",\"b64\":false,\"crit\":[\"b64\"]}"
  
  # Base64 URL encode the header and payload
  b64_header <- b64(JOSE_header)
  b64_payload <- b64(payload)
  
  # Create signing input
  signing_input <- paste0(b64_header, ".", b64_payload)
  
  # Sign the input
  b64_signature <- b64(sign(signing_input, signing_key))
  
  # Concatenate the parts into the JWS compact serialization
  return(paste(b64_header, b64_payload, b64_signature, sep = "."))
}

#' Deserialize a JWS Compact Serialization
#'
#' This function splits a JWS Compact Serialization into its component parts: header, payload, and signature.
#' It decodes the Base64 URL encoded parts back into readable formats.
#'
#' @param jws A JWS compact serialization string.
#' @return A list containing the decoded header, payload, and signature.
#' @examples
#' deserialize_jws(my_jws_string)
deserialize_jws <- function(jws) {
  parts <- strsplit(jws, "\\.")[[1]]
  
  # Decode each part from base64 URL to string
  header <- rawToChar(base64enc::base64decode(parts[1]))
  payload <- rawToChar(base64enc::base64decode(parts[2]))
  signature <- base64enc::base64decode(parts[3])
  
  return(list(header = header, payload = payload, signature = signature))
}

#' Verify a JWS signature
#'
#' This function verifies the signature of a JWS using the secp256k1 public key.
#' It decodes the JWS, reconstructs the signing input, and checks if the signature matches the input.
#'
#' @param jws A JWS compact serialization string to be verified.
#' @param public_key The secp256k1 public key used for verifying the signature.
#' @return A list containing the payload and public key if verification is successful, otherwise an error is raised.
#' @examples
#' verify(my_jws_string, my_public_key)
verify <- function(jws, public_key) {
  parts <- strsplit(jws, "\\.")[[1]]
  signing_input <- paste0(parts[1], ".", parts[2])
  signature <- base64decode(parts[3])
  
  # Verify the signature with the public key
  valid <- signature_verify(charToRaw(signing_input), signature, public_key, hash = "sha256")
  
  if (!valid) {
    stop("JWS verification failed.")
  }
  
  # Return the decoded payload
  payload <- rawToChar(base64decode(parts[2]))
  return(list(payload = payload, pubkey = public_key))
}

