
#' Normalize a String for Consistent Hashing
#'
#' This function normalizes a string using the NFKC normalization form.
#'
#' @param s A character string to be normalized.
#'
#' @return A character string that has been normalized to the NFKC form.
#'
#' @examples
#' normalized_string <- normalize_string("Café")
#' print(normalized_string)
#'
#' @import stringi
#' @export
normalize_string <- function(s) {
  # Normalize the string using NFKC form
  normalized <- stringi::stri_trans_nfc(s) # NFKC normalization in R
  return(normalized)
}
