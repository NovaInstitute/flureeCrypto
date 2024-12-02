library(testthat)
library(flureeCrypto)
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
context("Hash String Key")
# -----------------------------------------------------------------------------
test_that("Hash-string-key test", {
  actual_output <- hash_string_key("hello", 32)
  expected_output <- c(117, -43, 39, -61, 104, -14, -17, -24, 72, -20, -10, -80, 115, -93, 103, 103, -128, 8, 5, -23, -18, -14, -79, -123, 125, 95, -104, 79, 3, 110, -74, -33)
  
  expect_equal(actual_output, expected_output)
  
})


# -----------------------------------------------------------------------------
context("Normalize String")
# -----------------------------------------------------------------------------

test_that("Normalize string test", {
  # Generate a random string of length 10
  rdm_str <- paste(sample(letters, 10, replace = TRUE), collapse = "")
  
  # Test 1: The length of the normalized string should remain 10
  expect_equal(nchar(normalize_string(rdm_str)), 10)
  
  # Test 2: Create a map of composed-decomposed string pairs
  composed <- "\u00e9"  # 'é' (composed)
  decomposed <- "e\u0301"  # 'e' + '´' (decomposed)
  
  #cat("Composed (before normalization): ", composed, "\n")
  #cat("Decomposed (before normalization): ", decomposed, "\n")
  
  normalized_composed <- normalize_string(composed)
  normalized_decomposed <- normalize_string(decomposed)
  
  #cat("Normalized Composed: ", normalized_composed, "\n")
  #cat("Normalized Decomposed: ", normalized_decomposed, "\n")
  
  expect_equal(normalized_composed, normalized_decomposed)
  expect_false(identical(composed, decomposed))
})


# -----------------------------------------------------------------------------
context("String <-> Byte Conversions")
# -----------------------------------------------------------------------------

# Test string to byte (and byte to string) conversion
test_that("String to byte conversions and back", {
  
  input <- "hi there"
  
  # Convert the string to a byte array
  output <- string_to_byte_array(input)
  
  # Define the expected output
  expected_output <- c(104, 105, 32, 116, 104, 101, 114, 101)
  
  # Compare the result to the expected output
  expect_equal(output, expected_output)
})
