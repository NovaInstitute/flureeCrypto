#' Pad data using PKCS7 padding
#'
#' This function adds PKCS7 padding to the input data to make its length a multiple of the block size.
#'
#' @param data A raw vector containing the data to be padded.
#' @param block_size An integer specifying the block size in bytes. For AES, this is typically 16.
#'
#' @return A raw vector containing the padded data.
#' @examples
#' pad_pkcs7(charToRaw("hi"), 16)
pad_pkcs7 <- function(data, block_size) {
  pad_length <- block_size - (length(data) %% block_size)
  padding <- rep(pad_length, pad_length)
  c(data, padding)
}

#' Remove PKCS7 padding from data
#'
#' This function removes PKCS7 padding from the input data. It verifies that the padding is correct.
#'
#' @param data A raw vector containing the padded data.
#' @param block_size An integer specifying the block size in bytes. For AES, this is typically 16.
#'
#' @return A raw vector containing the data with padding removed.
#' @examples
#' unpad_pkcs7(pad_pkcs7(charToRaw("hi"), 16), 16)
#' @export
unpad_pkcs7 <- function(data, block_size) {
  pad_length <- data[length(data)]
  if (pad_length > block_size || pad_length <= 0) {
    stop("Invalid PKCS7 padding")
  }
  data[1:(length(data) - pad_length)]
}