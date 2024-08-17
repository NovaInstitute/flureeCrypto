#' AES Encryption with CBC Mode
#'
#' This function encrypts data using AES encryption in CBC mode with PKCS7 padding (compatible with PKCS5).
#'
#' @param iv A raw vector representing the initialization vector (IV).
#' @param key A raw vector representing the key for AES encryption. It should be exactly 16, 24, or 32 bytes.
#' @param data A raw vector representing the data to be encrypted.
#'
#' @return A raw vector representing the encrypted data.
#'
#' @import openssl
#' @export
encrypt_aes_cbc <- function(iv, key, data) {
  # Ensure the key is 16, 24, or 32 bytes
  if (length(key) != 16 && length(key) != 24 && length(key) != 32) {
    stop("Key must be 16, 24, or 32 bytes long.")
  }

  # Perform AES encryption in CBC mode with PKCS7 padding
  encrypted_data <- openssl::aes_cbc_encrypt(data, key = key, iv = iv)

  return(encrypted_data)
}


#' Encrypt with AES/CBC/PKCS7Padding
#'
#' Encrypts the input using AES encryption in CBC mode with PKCS7 padding. The key is hashed to 256 bits.
#' You can provide an alternate initialization vector (IV) of unsigned bytes of size 16 for CBC.
#'
#' @param x The input to be encrypted, either a character string or a raw vector.
#' @param key The encryption key as a character string or raw vector. It will be hashed to 256 bits if provided as a string.
#' @param iv A raw vector representing the initialization vector (IV). Defaults to a pre-defined 16-byte vector.
#' @param output_format The format of the output. Options are "hex" (default), "base64", or "none" for raw bytes.
#'
#' @return The encrypted data in the specified format.
#'
#' @import openssl
#' @import sodium
#' @export
#' @examples
#' # Example usage:
#' encrypted <- encrypt_aes("Hello, World!", "mysecretkey")
#' print(encrypted)
encrypt_aes <- function(x, key, iv = as.raw(c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)),
                        output_format = "hex") {

  # Convert the key to a 256-bit hash if it's a character string
  if (is.character(key)) {
    key <- sha256(charToRaw(key))
  } else if (!is.raw(key)) {
    stop("Key must be a character string or a raw vector.")
  }

  # Convert the input to a raw vector if it's a character string
  if (is.character(x)) {
    x <- charToRaw(x)
  } else if (!is.raw(x)) {
    stop("Input must be a character string or a raw vector.")
  }

  # Perform AES encryption using the encrypt_aes_cbc function
  encrypted_data <- encrypt_aes_cbc(iv, key, x)

  # Return the encrypted data in the specified output format
  if (output_format == "hex") {
    return(bin2hex(encrypted_data))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(encrypted_data))
  } else if (output_format == "none") {
    return(encrypted_data)
  } else {
    stop("Unsupported output format. Use 'hex', 'base64', or 'none'.")
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

#' AES Encryption Wrapper Function
#'
#' Encrypts the input using AES encryption in CBC mode with PKCS7 padding, with default output format as hexadecimal.
#'
#' @param x The input to be encrypted, either a character string or a raw vector.
#' @param iv A raw vector representing the initialization vector (IV).
#' @param key The encryption key as a character string or raw vector. It will be hashed to 256 bits if provided as a string.
#' @param output_format The format of the output. Options are "hex" (default), "base64", or "none" for raw bytes.
#'
#' @return The encrypted data in the specified format.
#'
#' @examples
#' aes_encrypt("Encrypt this message!", charToRaw("thisisaniv123456"), "mysecretpassword")
#'
#' @import openssl
#' @export
aes_encrypt <- function(x, iv, key, output_format = "hex") {
  encrypt_aes(x, key, iv, output_format = output_format)
}
#' AES Decryption Wrapper Function
#'
#' Decrypts the input using AES decryption in CBC mode with PKCS7 padding, with default input format as hexadecimal and output format as a string.
#'
#' @param x The input to be decrypted, either a character string or a raw vector.
#' @param iv A raw vector representing the initialization vector (IV).
#' @param key The decryption key as a character string or raw vector. It will be hashed to 256 bits if provided as a string.
#' @param output_format The format of the output. Options are "string" (default), "hex", or "none" for raw bytes.
#' @param input_format The format of the encrypted input. Options are "hex" (default) or "base64".
#'
#' @return The decrypted data in the specified format.
#'
#' @examples
#' encrypted_hex <- aes_encrypt("Encrypt this message!", charToRaw("thisisaniv123456"), "mysecretpassword")
#' aes_decrypt(encrypted_hex, charToRaw("thisisaniv123456"), "mysecretpassword")
#'
#' @import openssl
#' @export
aes_decrypt <- function(x, iv, key, output_format = "string", input_format = "hex") {
  decrypt_aes(x, key, iv, input_format = input_format, output_format = output_format)
}






