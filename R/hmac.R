
#' HMAC-SHA256
#' @description Returns HMAC using SHA-256 hashing. Both key and message should be raw vectors.
#'
#' @param message A raw vector representing the message.
#' @param key A raw vector representing the key.
#' @param output_format The format of the output hash. Options are "hex", "base64", or "raw" (default).
#'
#' @return A character string (if "hex" or "base64") or raw vector (if "raw") containing the HMAC-SHA256 result.
#' @import digest
#' @export
#' @examples
#' # => (require '[alphabase.core :as alphabase])
#' # => (def message (.getBytes "hello"))
#' # => (def key (.getBytes "secret"))
#' # => (println (alphabase/bytes->hex (hmac-sha256 message key)))
#' # 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
#' hmac_sha256(message = charToRaw("hello"), key = charToRaw("secret"))
#' hmac_sha256(message = charToRaw("hello"), key = charToRaw("secret"), output_format = "hex")
#' # "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"

hmac_sha256 <- function(message, key, output_format = c("hex", "base64", "raw")[3]) {
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
                              serialize = FALSE,
                              raw = TRUE)

  # Convert the result back to raw
  if (output_format == "hex") {
    return(bin2hex(hmac_result))
  } else if (output_format == "base64") {
    return(base64enc::base64encode(hmac_result))
  } else if (output_format == "raw") {
    return(hmac_result)
  } else {
    stop("Unsupported output format. Choose from 'raw', 'hex' or 'base64'.")
  }

}
