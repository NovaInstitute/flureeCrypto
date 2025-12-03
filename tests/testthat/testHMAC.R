library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("HMAC-SHA256")
# -----------------------------------------------------------------------------

test_that("HMAC-SHA256 produces correct hash", {
  # Test case from documentation
  message <- charToRaw("hello")
  key <- charToRaw("secret")
  
  # Test hex output format
  result_hex <- hmac_sha256(message, key, output_format = "hex")
  expected <- "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
  expect_equal(result_hex, expected)
})

test_that("HMAC-SHA256 output format variations", {
  message <- charToRaw("test message")
  key <- charToRaw("test key")
  
  # Test hex format
  result_hex <- hmac_sha256(message, key, output_format = "hex")
  expect_true(is.character(result_hex))
  expect_equal(nchar(result_hex), 64)  # SHA-256 produces 32 bytes = 64 hex chars
  
  # Test base64 format
  result_base64 <- hmac_sha256(message, key, output_format = "base64")
  expect_true(is.character(result_base64))
  
  # Test raw format (default)
  result_raw <- hmac_sha256(message, key, output_format = "raw")
  expect_true(is.raw(result_raw))
  expect_equal(length(result_raw), 32)  # SHA-256 produces 32 bytes
})

test_that("HMAC-SHA256 validates input types", {
  # Should throw error if message is not raw
  expect_error(hmac_sha256("not raw", charToRaw("key")), 
               "Both message and key should be raw vectors.")
  
  # Should throw error if key is not raw
  expect_error(hmac_sha256(charToRaw("message"), "not raw"), 
               "Both message and key should be raw vectors.")
})

test_that("HMAC-SHA256 handles different message lengths", {
  key <- charToRaw("constant key")
  
  # Short message
  msg1 <- charToRaw("hi")
  result1 <- hmac_sha256(msg1, key, output_format = "hex")
  expect_equal(nchar(result1), 64)
  
  # Long message
  msg2 <- charToRaw(paste(rep("a", 1000), collapse = ""))
  result2 <- hmac_sha256(msg2, key, output_format = "hex")
  expect_equal(nchar(result2), 64)
  
  # Different messages should produce different HMACs
  expect_false(result1 == result2)
})

test_that("HMAC-SHA256 handles different key lengths", {
  message <- charToRaw("constant message")
  
  # Short key
  key1 <- charToRaw("k")
  result1 <- hmac_sha256(message, key1, output_format = "hex")
  
  # Long key
  key2 <- charToRaw(paste(rep("k", 100), collapse = ""))
  result2 <- hmac_sha256(message, key2, output_format = "hex")
  
  # Different keys should produce different HMACs
  expect_false(result1 == result2)
})
