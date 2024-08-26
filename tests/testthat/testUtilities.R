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
  
  # Test the examples given in the documentation
  input <- "hi there"
  
  # Convert the string to a byte array
  output <- string_to_byte_array(input)
  
  # Define the expected output
  expected_output <- c(104, 105, 32, 116, 104, 101, 114, 101)
  
  # Compare the result to the expected output
  expect_equal(byte_array, expected_output)
})





# -----------------------------------------------------------------------------
#     SHA2-256 
context("sha2-256")
# -----------------------------------------------------------------------------
composed_decomposed_df <- data.frame(
  composed = c("\u00e9", "\u00e2"),
  decomposed = c("e\u0301", "a\u0302"),
  stringsAsFactors = FALSE
)

test_that("SHA2-256 Hash Length and Uniqueness", {
  rdm_strs <- replicate(10, {
    random_string <- function(n) {
      paste0(sample(c(letters, LETTERS, 0:9), n, replace = TRUE), collapse = "")
    }
    random_string(sample(1:1000, 1))
  })
  
  # Test that the SHA-256 hash of each string is 64 characters long
  expect_true(all(sapply(rdm_strs, function(x) nchar(sha2_256(x, output_format = "hex")) == 64)))
  
  # Test that the SHA-256 hash of the composed form is not equal to the hash of the decomposed for
  expect_true(all(apply(composed_decomposed_df, 1, function(row) {
    composed_hash <- sha2_256(row["composed"], output_format = "hex")
    decomposed_hash <- sha2_256(row["decomposed"], output_format = "hex")
    return(composed_hash != decomposed_hash)
  })))
  
  # Test the examples given in the documentation
  test_cases <- data.frame(
    input = c("\u0041\u030apple"),
    expected_output = c("6e9288599c1ff90127459f82285327c83fa0541d8b7cd215d0cd9e587150c15f"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha2_256(input), expected_output)
  }
  
})

context("sha2-256_normalize")
test_that("SHA2-256 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of each SHA2-256 normalized hash should be 64 characters
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha2_256_normalize(s)) == 64
  })))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(apply(composed_decomposed_df, 1, function(row) {
    composed_hash <- sha2_256_normalize(row["composed"], output_format = "hex")
    decomposed_hash <- sha2_256_normalize(row["decomposed"], output_format = "hex")
    return(composed_hash == decomposed_hash)
  })))

  # Test the examples given in the documentation
  test_cases <- data.frame(
    input = c("\u0041\u030apple"),
    expected_output = c("58acf888b520fe51ecc0e4e5eef46c3bea3ca7df4c11f6719a1c2471bbe478bf"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha2_256_normalize(input), expected_output)
  }
})





# -----------------------------------------------------------------------------
#     SHA2-512
context("sha2-512")
# -----------------------------------------------------------------------------
test_that("SHA2-512 Hash Length and Uniqueness", {
  rdm_strs <- replicate(10, {
    random_string <- function(n) {
      paste0(sample(c(letters, LETTERS, 0:9), n, replace = TRUE), collapse = "")
    }
    random_string(sample(1:1000, 1))
  })
  
context("length")
  # Test that the SHA-512 hash of each string is 128 characters long
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha2_512(s)) == 128
  })))
  
context("identical")
  # Test that the SHA-512 hash of the composed form is not equal to the hash of the decomposed for
  expect_false(all(mapply(function(comp, decomp) {
    identical(sha2_512(comp), sha2_512(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})

context("sha2-512_normalized")
test_that("SHA2-512 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of each SHA2-512 normalized hash should be 128 characters
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha2_512_normalize(s)) == 128
  })))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(mapply(function(comp, decomp) {
    identical(sha2_512_normalize(comp), sha2_512_normalize(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})





# -----------------------------------------------------------------------------
#     SHA3-256 
context("SHA3-256")
# -----------------------------------------------------------------------------
composed_decomposed_df <- data.frame(
  composed = c("\u00e9", "\u00e2"),
  decomposed = c("e\u0301", "a\u0302"),
  stringsAsFactors = FALSE
)

test_that("SHA3-256 Hash Length and Uniqueness", {
  rdm_strs <- replicate(10, {
    random_string <- function(n) {
      paste0(sample(c(letters, LETTERS, 0:9), n, replace = TRUE), collapse = "")
    }
    random_string(sample(1:1000, 1))
  })
  
  # Test that the SHA-256 hash of each string is 64 characters long
  expect_true(all(sapply(rdm_strs, function(x) nchar(sha3_256(x, output_format = "hex")) == 64)))
  
  # Test that the SHA-256 hash of the composed form is not equal to the hash of the decomposed for
  expect_false(all(mapply(function(comp, decomp) {
    identical(sha3_256(comp), sha3_256(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})

context("sha3-256_normalize")
test_that("SHA3-256 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of each SHA2-256 normalized hash should be 64 characters
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha3_256_normalize(s)) == 64
  })))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(mapply(function(comp, decomp) {
    identical(sha3_256_normalize(comp), sha3_256_normalize(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})


# -----------------------------------------------------------------------------
#     SHA3-512
context("SHA3-512")
# -----------------------------------------------------------------------------
composed_decomposed_df <- data.frame(
  composed = c("\u00e9", "\u00e2"),
  decomposed = c("e\u0301", "a\u0302"),
  stringsAsFactors = FALSE
)

test_that("SHA3-512 Hash Length and Uniqueness", {
  rdm_strs <- replicate(10, {
    random_string <- function(n) {
      paste0(sample(c(letters, LETTERS, 0:9), n, replace = TRUE), collapse = "")
    }
    random_string(sample(1:1000, 1))
  })
  
  # Test that the SHA-256 hash of each string is 64 characters long
  expect_true(all(sapply(rdm_strs, function(x) nchar(sha3_512(x, output_format = "hex")) == 128)))
  
  # Test that the SHA-256 hash of the composed form is not equal to the hash of the decomposed for
  expect_false(all(mapply(function(comp, decomp) {
    identical(sha3_512(comp), sha3_512(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})

context("sha3-512_normalize")
test_that("SHA3-512 Normalize Hash Length and Consistency", {
  set.seed(123)
  rdm_strs <- replicate(10, paste0(sample(c(letters, LETTERS, 0:9), size = sample(1:1000, 1), replace = TRUE), collapse = ""))
  
  # Test 1: The length of each SHA2-256 normalized hash should be 64 characters
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha3_512_normalize(s)) == 128
  })))
  
  # Test 2: Normalized hashes of composed and decomposed strings should be equal
  expect_true(all(mapply(function(comp, decomp) {
    identical(sha3_512_normalize(comp), sha3_512_normalize(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
})
  
  

#  2 hours sha2-256 tests 
# 3 hours to finish hash function tests.
  
  
  
  
  
  