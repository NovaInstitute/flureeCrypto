library(testthat)
library(flureeCrypto)
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
#     HASH STRING KEY
context("hash-string-key")
# -----------------------------------------------------------------------------
test_that("Hash-string-key test", {
  actual_output <- hash_string_key("hello", 32)
  expected_output <- c(117, -43, 39, -61, 104, -14, -17, -24, 72, -20, -10, -80, 115, -93, 103, 103, -128, 8, 5, -23, -18, -14, -79, -123, 125, 95, -104, 79, 3, 110, -74, -33)
  
  expect_equal(actual_output, expected_output)
  
})

result <- hash_string_key("there")
result
class(result)


# -----------------------------------------------------------------------------
#     NORMALIZED STRING 
context("Normalize string test")
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
  
  context("Test given in documentation")
  # Test the examples given in the documentation
  input <- "hi there"
  
  # Convert the string to a byte array
  output <- string_to_byte_array(input)
  
  # Define the expected output
  expected_output <- c(104, 105, 32, 116, 104, 101, 114, 101)
  
  # Compare the result to the expected output
  expect_equal(output, expected_output)
})





# -----------------------------------------------------------------------------
#     SHA2-256 
context("sha2-256")
# -----------------------------------------------------------------------------
composed_decomposed_df <- data.frame(
  composed = c("\u00C5", "\u212B", "\u00e9"),
  decomposed = c("\u0041\u030a", "\u0041\u030a", "\u0065\u0301"),
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
  context("Tests given in documentation")
  test_cases <- data.frame(
    input = c("\u0041\u030apple", "hi"),
    expected_output = c("6e9288599c1ff90127459f82285327c83fa0541d8b7cd215d0cd9e587150c15f", "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"),
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
  context("Tests given in documentation")
  test_cases <- data.frame(
    input = c("\u0041\u030apple", "hi"),
    expected_output = c("58acf888b520fe51ecc0e4e5eef46c3bea3ca7df4c11f6719a1c2471bbe478bf", "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"),
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
  
  # Test that the SHA-512 hash of each string is 128 characters long
  expect_true(all(sapply(rdm_strs, function(s) {
    nchar(sha2_512(s)) == 128
  })))
  
  # Test that the SHA-512 hash of the composed form is not equal to the hash of the decomposed for
  expect_false(all(mapply(function(comp, decomp) {
    identical(sha2_512(comp), sha2_512(decomp))
  }, composed_decomposed_df$composed, composed_decomposed_df$decomposed)))
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha2_512(input), expected_output)
  }
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
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("150a14ed5bea6cc731cf86c41566ac427a8db48ef1b9fd626664b3bfbb99071fa4c922f33dde38719b8c8354e2b7ab9d77e0e67fc12843920a712e73d558e197"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha2_512_normalize(input), expected_output)
  }
})





# -----------------------------------------------------------------------------
#     SHA3-256 
context("SHA3-256")
# -----------------------------------------------------------------------------

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
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("b39c14c8da3b23811f6415b7e0b33526d7e07a46f2cf0484179435767e4a8804"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha3_256(input), expected_output)
  }
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
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("b39c14c8da3b23811f6415b7e0b33526d7e07a46f2cf0484179435767e4a8804"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha3_256_normalize(input), expected_output)
  }
})


# -----------------------------------------------------------------------------
#     SHA3-512
context("SHA3-512")
# -----------------------------------------------------------------------------

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
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("154013cb8140c753f0ac358da6110fe237481b26c75c3ddc1b59eaf9dd7b46a0a3aeb2cef164b3c82d65b38a4e26ea9930b7b2cb3c01da4ba331c95e62ccb9c3"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha3_512(input), expected_output)
  }
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
  
  # Test the example given in the documentation
  context("Test given in documentation")
  test_cases <- data.frame(
    input = c("hi"),
    expected_output = c("154013cb8140c753f0ac358da6110fe237481b26c75c3ddc1b59eaf9dd7b46a0a3aeb2cef164b3c82d65b38a4e26ea9930b7b2cb3c01da4ba331c95e62ccb9c3"),
    stringsAsFactors = FALSE
  )
  
  # Test each case
  for (i in seq_len(nrow(test_cases))) {
    input <- test_cases$input[i]
    expected_output <- test_cases$expected_output[i]
    expect_equal(sha3_512_normalize(input), expected_output)
  }
})





# -----------------------------------------------------------------------------
#     ripemd-160
context("ripemd-160")
# -----------------------------------------------------------------------------

test_that("RIPEMD-160 Hash", {
  # Compute the hash
  hash_result <- ripemd_160("hi there!")
  
  # Check if the result matches the expected hash
  expect_equal(hash_result, "ad6ce46f7f1ea8519dc02ce8ce0c278c6ff329b2")
})





# -----------------------------------------------------------------------------
#     AES Encrypt
context("aes-encrypt")
# -----------------------------------------------------------------------------

test_that("AES Encrypt", {
  initialization_vector = as.raw(c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42))
  message = "hi"
  key = "there"
  
  output = encrypt(message, key, initialization_vector)
  
  # Check if the result matches the expected hash
  expect_equal(output, "668cd07d1a17cc7a8a0390cf017ac7ef")
})

# -----------------------------------------------------------------------------
#     AES Decrypt
context("aes-decrypt")
# -----------------------------------------------------------------------------

test_that("AES Decrypt", {
  initialization_vector = as.raw(c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42))
  message = "hi"
  key = "there"
  encrypted = encrypt(message, key, initialization_vector)
  decrypted = decrypt(encrypted, key, initialization_vector)
  
   # Check if the result matches the expected hash
  expect_equal(decrypted, "hi")
})





# -----------------------------------------------------------------------------
#     Generate Keypair
context("generate keypair")
# -----------------------------------------------------------------------------

#library(stringr)
#keypair <- generate_keypair()
#print(keypair$public)
#print(keypair$private)
#raw_private_key <- hex2bin(keypair$private)
#is_valid_private_key(raw_private_key)

#keypair <- generate_keypair(raw_private_key)
#print(keypair$public)
#print(keypair$private)

#message = "hi there"
#privateKey = "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2"
#signature <- sign_hash(message, privateKey)
#signature

#str_length(signature)
#str_length("1b3046022100cbd32e463567fefc2f120425b0224d9d263008911653f50e83953f47cfbef3bc022100fcf81206277aa1b86d2667b4003f44643759b8f4684097efd92d56129cd89ea8")

# biginteger
b <- as.bigz(12345678)
result <- biginteger_to_hex_R(b)
result

# modular square_root
n <- as.bigz(9)
modulus <- as.bigz(11)
result <- modular_square_root(n, modulus)

# Display the result
result

ba <- charToRaw("hello")
ba

byte_to_int(ba)

# compute a point
x <- as.bigz("1234567890123456789012345678901234567890")
curve <- list(n = as.bigz("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16))  # Example curve
result <- compute_point(TRUE, x, curve)
print(result)

# hmac 
message <- charToRaw("hello")
k <- charToRaw("secret")
result <- hmac_sha256(message, k)
result

# scrypt encrypt

message <- charToRaw("hello")
salt_bytes <- as.raw(c(-84, 28, -14, 108, -81, -126, -42, 6, -7, 61, -12, -78, 34, 8, 13, -78))
result <- encrypt(message, salt = salt_bytes)
bin2hex(result)

check(message, result, salt_bytes)
