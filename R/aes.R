#' Encrypt Data Using AES in CBC Mode
#'
#' This function performs AES encryption in CBC mode with PKCS#7 padding.
#'
#' @param iv A raw vector of length 16 representing the initialization vector.
#' @param key A raw vector of length 32 representing the AES key.
#' @param data A raw vector or character string representing the plaintext data to encrypt.
#' @return A raw vector representing the encrypted data.
#' @export
encrypt_aes_cbc <- function(iv, key, data) {
  # Ensure key and iv are raw vectors
  if (!is.raw(key)) {
    stop("Key must be a raw vector")
  }
  if (!is.raw(iv)) {
    iv <- as.raw(iv)
  }
  
  # Convert data to raw if it's a character string
  if (is.character(data)) {
    data <- charToRaw(data)
  }
  
  # Pad data with PKCS#7 padding
  print(class(data))
  padded_data <- as.raw(pad_pkcs7(data, 16))
  
  # Debugging prints
  print("Key (raw):")
  print(key)
  print("IV (raw):")
  print(iv)
  print("Padded data (raw):")
  print(padded_data)
  
  # Perform AES encryption in CBC mode
  encrypted_data <- aes_cbc_encrypt(padded_data, key, iv)
  
  print("Encrypted data (raw):")
  print(encrypted_data)
  
  return(encrypted_data)
}

#' Encrypt Data with AES/CBC/PKCS7 Padding
#'
#' @param x The input data to encrypt. This can be a character string or a raw vector.
#' @param key The encryption key. This can be a character string (hashed into a 256-bit key) or a raw vector.
#' @param iv An optional vector of unsigned bytes of size 16 to be used as the initialization vector. Defaults to a predefined IV.
#' @param output_format The desired format for the encrypted output: "hex", "base64", or "none".
#' @return The encrypted data in the specified output format.
#' @export
encrypt <- function(x, key, iv = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42), output_format = "hex") {
  # If key is a string, hash it into a 256-bit key (32 bytes)
  if (is.character(key)) {
    key <- hash_string_key(key)
    key <- charToRaw(key)
    print(class(key))
    print(key)
  }
  
  # Convert iv to raw vector if not already raw
  if (!is.raw(iv)) {
    iv <- as.raw(iv)
  }
  
  # Convert input data (x) to raw bytes if it's a character string
  if (is.character(x)) {
    x <- charToRaw(x)
  }
  
  # Perform AES encryption
  encrypted <- encrypt_aes_cbc(iv, key, x)
  
  # Debugging prints
  print("Encrypted data (before formatting):")
  print(encrypted)
  
  # Convert encrypted output to desired format
  if (output_format == "hex") {
    hex_output <- paste(toupper(as.character(encrypted)), collapse = "")
    print("Encrypted data (hex):")
    print(hex_output)
    return(hex_output)
  } else if (output_format == "base64") {
    base64_output <- base64_encode(encrypted)
    print("Encrypted data (base64):")
    print(base64_output)
    return(base64_output)
  } else {
    return(encrypted)  # Return raw bytes by default
  }
}

#' AES Decryption with CBC Mode
#'
#' This function decrypts data using AES decryption in CBC mode with PKCS7 padding (compatible with PKCS5).
#'
#' @param iv A raw vector representing the initialization vector (IV).
#' @param key A raw vector representing the key for AES decryption. It should be exactly 16, 24, or 32 bytes.
#' @param encrypted_data A raw vector representing the data to be decrypted.
#'
#' @return A raw vector representing the decrypted data.
#'
#' @import openssl
#' @export
decrypt_aes_cbc <- function(iv, key, encrypted_data) {
  # Ensure the key is 16, 24, or 32 bytes
  if (length(key) != 16 && length(key) != 24 && length(key) != 32) {
    stop("Key must be 16, 24, or 32 bytes long.")
  }

  # Perform AES decryption in CBC mode with PKCS7 padding
  decrypted_data <- openssl::aes_cbc_decrypt(encrypted_data, key = key, iv = iv)

  return(decrypted_data)
}

#' Decrypt with AES/CBC/PKCS7Padding
#'
#' Decrypts the input using AES decryption in CBC mode with PKCS7 padding. The key is hashed to 256 bits.
#' You can provide an alternate initialization vector (IV) of unsigned bytes of size 16 for CBC.
#'
#' @param x The input to be decrypted, either a character string or a raw vector.
#' @param key The decryption key as a character string or raw vector. It will be hashed to 256 bits if provided as a string.
#' @param iv A raw vector representing the initialization vector (IV). Defaults to a pre-defined 16-byte vector.
#' @param input_format The format of the encrypted input. Options are "hex" (default) or "base64".
#' @param output_format The format of the output. Options are "string" (default), "hex", or "none" for raw bytes.
#'
#' @return The decrypted data in the specified format.
#'
#' @import openssl
#' @import sodium
#' @export
#' @examples
#' encrypted_hex <- encrypt_aes("Encrypt this message!", "mysecretpassword")
#' decrypted_text <- decrypt_aes(encrypted_hex, "mysecretpassword")
#' print(decrypted_text)  # Outputs: "Encrypt this message!"
#' encrypted_base64 <- encrypt_aes("Encrypt this message!", "mysecretpassword", output_format = "base64")
#' decrypted_text <- decrypt_aes(encrypted_base64, "mysecretpassword", input_format = "base64")
#' print(decrypted_text)  # Outputs: "Encrypt this message!"

decrypt_aes <- function(x, key, iv = as.raw(c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)),
                        input_format = "hex", output_format = "string") {

  # Convert the key to a 256-bit hash if it's a character string
  if (is.character(key)) {
    key <- sha256(charToRaw(key))
  } else if (!is.raw(key)) {
    stop("Key must be a character string or a raw vector.")
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
  decrypted_data <- decrypt_aes_cbc(iv, key, x)

  # Return the decrypted data in the specified output format
  if (output_format == "string") {
    return(rawToChar(decrypted_data))
  } else if (output_format == "hex") {
    return(bin2hex(decrypted_data))
  } else if (output_format == "none") {
    return(decrypted_data)
  } else {
    stop("Unsupported output format. Use 'string', 'hex', or 'none'.")
  }
}






