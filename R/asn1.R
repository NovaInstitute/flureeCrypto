#' Encode ASN.1 Length to Hexadecimal
#'
#' Converts a length into its hexadecimal string representation for ASN.1 encoding.
#'
#' @param len An integer representing the length to encode.
#' @return A string containing the hexadecimal representation of the length.
encode_asn1_length_hex <- function(len) {
  toupper(as.hexmode(len))
}

#' Decode ASN.1 Length
#'
#' Decodes the length from an ASN.1 encoded string, throwing an error for unsupported lengths.
#'
#' @param asn1 A string containing the ASN.1 encoded data.
#' @return A list with two elements: the decoded length and the remaining ASN.1 string.
decode_asn1_length <- function(asn1) {
  len <- as.integer(substring(asn1, 1, 2), 16)
  
  if (bitwAnd(len, 0x80) != 0) {
    stop("Lengths greater than 0x80 not supported")
  }
  
  list(length = len, remaining = substring(asn1, 3))
}

#' Format ASN.1 Unsigned Integer (Hexadecimal)
#'
#' Formats a hexadecimal-encoded unsigned integer by removing leading zeros and padding if necessary to avoid two's complement confusion.
#'
#' @param n A hexadecimal string representing an unsigned integer.
#' @return A string containing the formatted hexadecimal representation.
format_asn1_unsigned_integer_hex <- function(n) {
  bytes <- rawToBits(as.raw(strtoi(n, base=16L)))
  bytes <- bytes[!duplicated(bytes == 0)]  # Drop leading zeros
  
  if (bitwAnd(as.integer(bytes[1]), 0x80) != 0) {
    bytes <- c(as.raw(0), bytes)  # Add padding if needed
  }
  
  toupper(paste(as.hexmode(as.integer(bytes)), collapse = ""))
}

#' Format ASN.1 Unsigned Integer (Byte Array)
#'
#' Formats a byte array representing an unsigned integer by removing leading zeros and padding if necessary.
#'
#' @param ba A byte array representing an unsigned integer.
#' @return A byte array with formatted unsigned integer.
format_asn1_unsigned_integer <- function(ba) {
  bytes <- ba[ba != 0]  # Drop leading zeros
  
  if (bitwAnd(as.integer(bytes[1]), 0x80) != 0) {
    c(as.raw(0), bytes)  # Add padding if needed
  } else {
    bytes
  }
}

#' Encode ASN.1 Unsigned Integer (Hexadecimal)
#'
#' Encodes a hexadecimal string as an ASN.1 unsigned integer, including length and ASN.1 integer tag.
#'
#' @param n A hexadecimal string representing an unsigned integer.
#' @return A string containing the ASN.1 encoded unsigned integer.
encode_asn1_unsigned_integer_hex <- function(n) {
  formatted_n <- format_asn1_unsigned_integer_hex(n)
  len <- encode_asn1_length_hex(nchar(formatted_n) / 2)
  paste0("02", len, formatted_n)
}

#' Encode ASN.1 Unsigned Integer (Byte Array)
#'
#' Encodes a byte array as an ASN.1 unsigned integer, including length and ASN.1 integer tag.
#'
#' @param ba A byte array representing an unsigned integer.
#' @return A byte array with the ASN.1 encoded unsigned integer.
encode_asn1_unsigned_integer <- function(ba) {
  formatted_n <- format_asn1_unsigned_integer(ba)
  size <- length(formatted_n)
  c(2, size, formatted_n)
}

#' Decode ASN.1 Integer
#'
#' Decodes an integer from the top of an ASN.1 encoded string. The function assumes the ASN.1 integer tag "02" is present.
#'
#' @param asn1 A string containing the ASN.1 encoded data.
#' @return A list with two elements: the decoded integer and the remaining ASN.1 string.
decode_asn1_integer <- function(asn1) {
  stopifnot(substring(asn1, 1, 2) == "02")
  decoded_length <- decode_asn1_length(substring(asn1, 3))
  list(
    integer = substring(decoded_length$remaining, 1, decoded_length$length * 2),
    remaining = substring(decoded_length$remaining, decoded_length$length * 2 + 1)
  )
}