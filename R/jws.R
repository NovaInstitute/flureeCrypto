library(jsonlite)  # For handling JSON
library(openssl)   # For base64url encoding/decoding and key handling
library(stringr)


# This is a standard header that is used with each jws serialization
jose_header <- "{\"alg\":\"ES256K-R\",\"b64\":false,\"crit\":[\"b64\"]}"


#' Base64 URL encode
#'
#' @description
#' This function encodes a given string into Base64 URL format and removes any 
#' trailing '=' padding. It is useful for encoding data in a URL-safe way 
#' without padding characters.
#'
#' @param input_string A string to be encoded.
#' 
#' @return A Base64 URL encoded string without padding.
#' 
#' @examples
#' b64("example string")
#' 
#' @importFrom base64enc base64encode
#' 
b64 <- function(input_string) {
  b64_string <- base64enc::base64encode(charToRaw(input_string))
  gsub("=+$", "", b64_string)
}

#' Create a JWS Compact Serialization
#'
#' @description
#' This function generates a JWS (JSON Web Signature) Compact Serialization from 
#' the provided payload and secp256k1 signing (private)  key. It first encodes 
#' the JOSE header and payload using Base64 URL encoding, then signs the message 
#' using the "sign_message" function (from secp256k1.R) and constructs the JWS string.
#'
#' @param payload The payload to be included in the JWS.
#' @param signing_key The secp256k1 signing key used to sign the payload.
#' 
#' @return A JWS compact serialization as a string.
#' 
#' @examples
#' serialize_jws("example payload", my_signing_key)
#' 
serialize_jws <- function(payload, signing_key) {
  # JOSE header
  JOSE_header <- "{\"alg\":\"ES256K-R\",\"b64\":false,\"crit\":[\"b64\"]}"
  
  # Base64 URL encode the header and payload
  b64_header <- b64(JOSE_header)
  b64_payload <- b64(payload)
  
  # Create signing input
  signing_input <- paste0(b64_header, ".", b64_payload)
  print(signing_input)
  
  # Sign the input
  raw_sig <- sign_message(signing_input, signing_key)
  b64_signature <- b64(sign_message(signing_input, signing_key))
  
  # Concatenate the parts into the JWS compact serialization
  return(paste(b64_header, b64_payload, b64_signature, sep = "."))
}

#' Deserialize a JWS Compact Serialization
#'
#' @description
#' This function splits a JWS Compact Serialization into its component parts: 
#' header, payload, and signature.
#' It decodes the Base64 URL encoded parts back into readable formats.
#'
#' @param jws A JWS compact serialization string.
#' 
#' @return A list containing the decoded header, payload, and signature.
#' 
#' @examples
#' deserialize_jws(my_jws_string)
#' 
#' @importFrom base64enc base64decode
#' 
deserialize_jws <- function(jws) {
  parts <- strsplit(jws, "\\.")[[1]]
  
  # Decode each part from base64 URL to string
  header <- rawToChar(base64enc::base64decode(parts[1]))
  payload <- rawToChar(base64enc::base64decode(parts[2]))
  signature <- bin2hex(base64enc::base64decode(parts[3]))
  
  return(list(header = header, payload = payload, signature = signature))
}

#' Verify a JWS signature
#' 
#' @description
#' This function verifies the signature of a JWS using the secp256k1 public key.
#' It decodes the JWS, reconstructs the signing input, and checks if the 
#' signature matches the input.
#'
#' @param jws A JWS compact serialization string to be verified.
#' @param public_key The secp256k1 public key used for verifying the signature
#' .
#' @return A list containing the payload and public key if verification is successful, otherwise an error is raised.
#' 
#' @examples
#' verify(my_jws_string, my_public_key)
verify_jws <- function(jws, public_key) {
  parts <- strsplit(jws, "\\.")[[1]]
  
  # Decode each part from base64 URL to string
  b64_header <- parts[1]
  b64_payload <- parts[2]
  
  header <- rawToChar(base64enc::base64decode(parts[1]))
  payload <- rawToChar(base64enc::base64decode(parts[2]))
  sig <- byte_array_to_string(base64enc::base64decode(parts[3]))
  print(signature)
  
  signing_input <- paste0(b64_header, ".", b64_payload)
  print(signing_input)
  print(class(signing_input))
  
  pub_key <- public_key_from_message(signing_input, sig)
  print(pub_key)
  
  # Verify the signature with the public key
  valid <- flureeCrypto::verify_signature(public_key, signing_input, signature)
  
  if (!valid) {
    stop("JWS verification failed.")
  }
  
  return(list(payload = payload, pubkey = public_key))
}

