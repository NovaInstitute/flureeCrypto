library(testthat)
library(flureeCrypto)
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
context("AES-Encrypt")
# -----------------------------------------------------------------------------

test_that("AES Encrypt", {
  initialization_vector = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
  message = "hi"
  key = "there"
  
  output = aes_encrypt(message, key, initialization_vector)
  
  # Check if the result matches the expected hash
  expect_equal(output, "668cd07d1a17cc7a8a0390cf017ac7ef")
})

# -----------------------------------------------------------------------------
context("AES-Decrypt")
# -----------------------------------------------------------------------------

test_that("AES Decrypt", {
  initialization_vector = c(6, 224, 71, 170, 241, 204, 115, 21, 30, 8, 46, 223, 106, 207, 55, 42)
  message = "hi"
  key = "there"
  encrypted = aes_encrypt(message, key, initialization_vector)
  decrypted = aes_decrypt(encrypted, key, initialization_vector)
  
  # Check if the result matches the expected hash
  expect_equal(decrypted, "hi")
})


# -----------------------------------------------------------------------------
context("Scrypt Encrypt")
# -----------------------------------------------------------------------------

test_that("Encrypt a message using scrypt encryption", {
  salt_bytes = c(172, 28, 242, 108, 175, 130, 214, 6, 249, 61, 244, 178, 34, 8, 13, 178)
  actual_output = scrypt_encrypt("hi", salt = salt_bytes)
  
  expect_equal(actual_output, "57f93bcf926c31a9e2d2129da84bfca51eb9447dfe1749b62598feacaad657d4")
})


# -----------------------------------------------------------------------------
context("Scrypt Check")
# -----------------------------------------------------------------------------

test_that("Check if message matches previous encryption output", {
  salt_bytes = c(172, 28, 242, 108, 175, 130, 214, 6, 249, 61, 244, 178, 34, 8, 13, 178)
  encrypted = scrypt_encrypt("hi", salt = salt_bytes, 32768, 8, 1)
  actual_output = scrypt_check("hi", "57f93bcf926c31a9e2d2129da84bfca51eb9447dfe1749b62598feacaad657d4", salt_bytes, 32768, 8, 1)
  
  expect_true(actual_output)
})
