#' @title HMAC-SHA256
#' @description Returns HMAC using SHA-256 hashing. Both key and message should be raw vectors.
#' @param message A raw vector representing the message.
#' @param key A raw vector representing the key.
#' @return A raw vector containing the HMAC-SHA256 result.
#' @import digest
#' @export
hmac_sha256 <- function(message, key) {
  # Ensure both inputs are raw vectors
  if (!is.raw(message) || !is.raw(key)) {
    stop("Both message and key should be raw vectors.")
  }
  
  # Convert raw vectors to character strings for hashing
  message_str <- rawToChar(message)
  key_str <- rawToChar(key)
  
  # Compute HMAC using SHA256
  hmac_result <- digest::hmac(key = key_str, 
                              object = message_str, 
                              algo = "sha256", 
                              serialize = FALSE)
  
  # Convert the result back to raw
  return(charToRaw(hmac_result))
}