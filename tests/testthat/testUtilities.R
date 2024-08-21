library(testthat)
library(flureeCrypto)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
#     NORMALIZED STRING 
context("Normalize string test")
# -----------------------------------------------------------------------------
library(stringi)

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
#     STRING <-> BYTE ARRAY 
context("String to byte conversions and back")
# -----------------------------------------------------------------------------

# Test string to byte (and byte to string) conversion
test_that("String to byte conversions and back", {
  set.seed(123)  # Set seed for reproducibility
  
  # Generate a list of 10 random strings of random lengths (up to 1000 characters)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Check that each string is the same after conversion to bytes and back
  expect_true(all(sapply(rdm_strs, function(s) {
    s == byte_array_to_string(string_to_byte_array(s))
  })))
})



# -----------------------------------------------------------------------------
#     SHA2-256 
context("sha2-256")
# -----------------------------------------------------------------------------
composed_decomposed_map <- list(
  "\u00e9" = "e\u0301",  # Example composed and decomposed strings
  "\u00e2" = "a\u0302"
)

test_that("SHA2-256 Hash Length and Uniqueness", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of the SHA2-256 hash should be 64 characters
  expect_true(all(nchar(sha2_256(rdm_strs)) == 64))
  
  # Test 2: Hashes of composed and decomposed strings should not be equal
  expect_true(all(sapply(composed_decomposed_map, function(v, k) {
    !identical(sha2_256(k), sha2_256(v))
  }, names(composed_decomposed_map))))
})

test_that("SHA2-256 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of the SHA2-256 normalized hash should be 64 characters
  expect_true(all(nchar(sha2_256_normalize(rdm_strs)) == 64))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(sapply(composed_decomposed_map, function(v, k) {
    identical(sha2_256_normalize(k), sha2_256_normalize(v))
  }, names(composed_decomposed_map))))
})




# -----------------------------------------------------------------------------
#     SHA2-512
context("sha2-512")
# -----------------------------------------------------------------------------
test_that("SHA2-512 Hash Length and Uniqueness", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of the SHA2-512 hash should be 128 characters
  expect_true(all(nchar(sha2_512(rdm_strs)) == 128))
  
  # Test 2: Hashes of composed and decomposed strings should not be equal
  expect_true(all(sapply(composed_decomposed_map, function(v, k) {
    !identical(sha2_512(k), sha2_512(v))
  }, names(composed_decomposed_map))))
})

test_that("SHA2-512 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of the SHA2-512 normalized hash should be 128 characters
  expect_true(all(nchar(sha2_512_normalize(rdm_strs)) == 128))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(sapply(composed_decomposed_map, function(v, k) {
    identical(sha2_512_normalize(k), sha2_512_normalize(v))
  }, names(composed_decomposed_map))))
})

# -----------------------------------------------------------------------------
#     SHA3-256 
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
#     SHA3-512
# -----------------------------------------------------------------------------