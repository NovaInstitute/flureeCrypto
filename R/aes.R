
#' Encrypt data using AES
#' 
#' @description
#' This internal helper function performs AES encryption in CBC mode with PKCS#7 padding.
#' It is called from the "aes_encrypt" function after all the necessary 
#' conversions and type-checking has been done. This function should not be called directly.
#'
#' @param iv A raw vector of length 16 representing the initialization vector.
#' @param key A raw vector of length 32 representing the AES key.
#' @param data A raw vector representing the plain text data/message to encrypt.
#' 
#' @return A raw vector representing the encrypted data.
#' 
#' @keywords internal
#' 
encrypt_aes_cbc <- function(iv, key, data) {
  
  # Perform AES encryption in CBC mode
  aes <- AES(key, mode = "CBC", iv, padding = TRUE)
  encrypted_data <- aes$encrypt(data)
  
  return(encrypted_data)
}



#' Prepare data for AES encryption
#' 
#' @description
#' This function does the necessary type-checking and conversions of parameters
#' and then passes them to "encrypt_aes_cbc" for AES encryption.
#' It also transforms the result to the specified/default output format.
#'
#' @param x The input data to encrypt. This can be a character string or a raw vector.
#' @param key The encryption key. This can be a character string (hashed into a 256-bit key) or a raw vector.
#' @param iv An optional numeric vector of unsigned bytes of size 16 to be used as the initialization vector. Defaults to a predefined IV.
#' @param output_format The desired format for the encrypted output: "hex", "base64" or "none". Defaults to "hex".
#' 
#' @return The encrypted data in the specified output format.
#' 
#' @export
aes_encrypt <- function(x, key, iv = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42), output_format = "hex") {
  # If the provided key is a string, hash it into a 256-bit key (32 raw bytes).
  if (is.character(key)) {
    k <- hash_string_key(key)
    # convert to unsigned bytes (to get rid of possible negative values)
    k <- map_signed_to_unsigned(k)
    key_ba <- as.raw(k)
  } else if (is.raw(key)) {
    key_ba <- key
  } else {
    stop("Encryption key should be a character string or raw byte array.")
  }
  
  # Convert iv to unsigned bytes (to get rid of possible negative values)
  iv <- map_signed_to_unsigned(iv)
  
  # Convert the input data to raw bytes if it's a character string.
  if (is.character(x)) {
    ba <- charToRaw(x)
  }
  
  # Perform AES encryption by calling the helper function.
  encrypted <- encrypt_aes_cbc(iv, key_ba, ba)
  
  # Convert the result to the desired output format
  if (output_format == "hex") {
    hex_output <- bin2hex(encrypted)
    return(hex_output)
  } else if (output_format == "base64") {
    base64_output <- base64enc::base64encode(encrypted)
    return(base64_output)
  } else if (output_format == "none") {
    return(encrypted)  
  } else {
    stop("Unsupported output format: " + output_format)
  }
}



#' Decrypt data using AES
#' 
#' @description
#' This internal helper function decrypts a message using AES decryption in CBC mode with PKCS7 padding.
#' It receives the necessary input from the "aes_decrypt" function after all the 
#' necessary type-checking and conversions have been done. This function should not be called directly.
#'
#' @param iv A raw vector representing the initialization vector.
#' @param key A raw vector representing the key for AES decryption. It should be exactly 16, 24, or 32 bytes.
#' @param encrypted_data A raw vector representing the data to be decrypted.
#'
#' @return A raw vector representing the decrypted data.
#' 
#' @keywords internal
#' 
decrypt_aes_cbc <- function(iv, key, encrypted_data) {
  
  # Perform AES decryption in CBC mode with PKCS7 padding
  aes <- AES(key, mode = "CBC", iv, padding = TRUE)
  decrypted_data <- aes$decrypt(encrypted_data, raw = TRUE)

  return(decrypted_data)
}



#' Data conversion before and after AES decryption
#'
#' @description
#' Decrypts the input using AES decryption in CBC mode with PKCS7 padding. 
#' The key is hashed to 256 bits.
#' An alternate initialization vector (IV) of unsigned bytes of size 16 my be 
#' provided.
#'
#' @param x The input to be decrypted, either a character string or a raw vector.
#' @param key The decryption key as a character string or raw vector. It will be hashed to 256 bits if provided as a string.
#' @param iv A numeric vector representing the initialization vector (IV). Defaults to a pre-defined 16-byte vector.
#' @param input_format The format of the encrypted input. Options are "hex" (default) or "base64".
#' @param output_format The format of the output. Options are "string" (default), "hex", or "none" for raw bytes.
#'
#' @return The decrypted data in the specified format.
#' 
#' @export
aes_decrypt <- function(x, key, iv = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42),
                        input_format = "hex", output_format = "string") {

  # Convert the key to a 256-bit hash if it's a character string
  if (is.character(key)) {
    k <- hash_string_key(key)
    # convert to unsigned bytes (to get rid of possible negative values)
    k <- map_signed_to_unsigned(k)
    key_ba <- as.raw(k)
  } else if (is.raw(key)) {
    key_ba <- key
  } else {
    stop("Key should be a character string or raw byte array")
  }
  
  if (length(key_ba) != 16 && length(key_ba) != 24 && length(key_ba) != 32) {
    stop("Key must be 16, 24, or 32 bytes long.")
  }

  # Convert the input to a raw vector if it's a character string in hex or base64 format
  if (is.character(x)) {
    if (input_format == "hex") {
      x <- hex2bin(x)
    } else if (input_format == "base64") {
      x <- base64enc::base64decode(x)
    } else {
      stop("Unsupported input format. Use 'hex' or 'base64'.")
    }
  } else if (!is.raw(x)) {
    stop("Input must be a character string or a raw vector.")
  }

  # Perform AES decryption using the decrypt_aes_cbc function
  decrypted <- decrypt_aes_cbc(iv, key_ba, x)

  # Return the decrypted data in the specified output format
  if (output_format == "string") {
    return(rawToChar(decrypted))
  } else if (output_format == "hex") {
    return(bin2hex(decrypted))
  } else if (output_format == "none") {
    return(decrypted_data)
  } else {
    stop("Unsupported output format. Use 'string', 'hex', or 'none'.")
  }
}