library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("Encoding Helper Functions")
# -----------------------------------------------------------------------------

test_that("pad_hex adds leading zero for odd-length strings", {
  # Test odd length
  result <- flureeCrypto:::pad_hex("abc")
  expect_equal(result, "0abc")
  
  # Test even length (should not change)
  result <- flureeCrypto:::pad_hex("abcd")
  expect_equal(result, "abcd")
  
  # Test single character
  result <- flureeCrypto:::pad_hex("a")
  expect_equal(result, "0a")
  
  # Test empty string
  result <- flureeCrypto:::pad_hex("")
  expect_equal(result, "")
})

test_that("byte_to_int converts first byte correctly", {
  # Test with ASCII characters
  bytes <- charToRaw("hello")
  result <- flureeCrypto:::byte_to_int(bytes)
  expect_equal(result, 104)  # ASCII value of 'h'
  
  # Test with raw bytes
  bytes <- as.raw(c(255, 128, 0))
  result <- flureeCrypto:::byte_to_int(bytes)
  expect_equal(result, 255)
})

test_that("byte_to_int validates input", {
  # Should error on non-raw input
  expect_error(flureeCrypto:::byte_to_int("not raw"), 
               "Input must be a raw byte vector.")
  expect_error(flureeCrypto:::byte_to_int(123), 
               "Input must be a raw byte vector.")
})

test_that("pad_to_length pads strings correctly", {
  # Test padding needed
  result <- flureeCrypto:::pad_to_length("42", 5)
  expect_equal(result, "00042")
  
  # Test no padding needed
  result <- flureeCrypto:::pad_to_length("12345", 3)
  expect_equal(result, "12345")
  
  # Test exact length
  result <- flureeCrypto:::pad_to_length("123", 3)
  expect_equal(result, "123")
  
  # Test empty string
  result <- flureeCrypto:::pad_to_length("", 3)
  expect_equal(result, "000")
})

# -----------------------------------------------------------------------------
context("Utility Conversion Functions")
# -----------------------------------------------------------------------------

test_that("map_excess_127 converts unsigned to signed bytes", {
  # Test conversion of values > 127
  v <- c(130, 120, 127, 255)
  result <- flureeCrypto:::map_excess_127(v)
  expect_equal(result, c(-126, 120, 127, -1))
  
  # Test boundary values
  expect_equal(flureeCrypto:::map_excess_127(c(0)), c(0))
  expect_equal(flureeCrypto:::map_excess_127(c(127)), c(127))
  expect_equal(flureeCrypto:::map_excess_127(c(128)), c(-128))
  expect_equal(flureeCrypto:::map_excess_127(c(255)), c(-1))
})

test_that("map_signed_to_unsigned converts signed to unsigned bytes", {
  # Test conversion of negative values
  v <- c(-5, 0, 10, -128, 127)
  result <- flureeCrypto:::map_signed_to_unsigned(v)
  expect_equal(result, c(251, 0, 10, 128, 127))
  
  # Test boundary values
  expect_equal(flureeCrypto:::map_signed_to_unsigned(c(0)), c(0))
  expect_equal(flureeCrypto:::map_signed_to_unsigned(c(127)), c(127))
  expect_equal(flureeCrypto:::map_signed_to_unsigned(c(-128)), c(128))
  expect_equal(flureeCrypto:::map_signed_to_unsigned(c(-1)), c(255))
})

test_that("map_signed_to_unsigned and map_excess_127 are inverse operations", {
  # Test round-trip conversion
  unsigned <- c(0, 127, 128, 255)
  signed <- flureeCrypto:::map_excess_127(unsigned)
  back_to_unsigned <- flureeCrypto:::map_signed_to_unsigned(signed)
  expect_equal(unsigned, back_to_unsigned)
})

test_that("coerce_input_format identifies input types correctly", {
  # Test string input
  result <- flureeCrypto:::coerce_input_format("hello")
  expect_equal(result, "string")
  
  # Test raw input
  result <- flureeCrypto:::coerce_input_format(charToRaw("hello"))
  expect_equal(result, "bytes")
  
  # Test error on unsupported type
  expect_error(flureeCrypto:::coerce_input_format(123), 
               "Unsupported input format")
  expect_error(flureeCrypto:::coerce_input_format(list(a = 1)), 
               "Unsupported input format")
})

test_that("hash_string_key produces consistent output", {
  # Test with string input
  result1 <- flureeCrypto:::hash_string_key("hello", 32)
  result2 <- flureeCrypto:::hash_string_key("hello", 32)
  expect_equal(result1, result2)
  
  # Test expected output from test suite
  actual_output <- flureeCrypto:::hash_string_key("hello", 32)
  expected_output <- c(117, -43, 39, -61, 104, -14, -17, -24, 72, -20, -10, -80, 115, -93, 103, 103, -128, 8, 5, -23, -18, -14, -79, -123, 125, 95, -104, 79, 3, 110, -74, -33)
  expect_equal(actual_output, expected_output)
})

test_that("hash_string_key handles different lengths", {
  # Test different output lengths
  result16 <- flureeCrypto:::hash_string_key("test", 16)
  expect_equal(length(result16), 16)
  
  result32 <- flureeCrypto:::hash_string_key("test", 32)
  expect_equal(length(result32), 32)
  
  result64 <- flureeCrypto:::hash_string_key("test", 64)
  expect_equal(length(result64), 64)
  
  # Should error if n > 64
  expect_error(flureeCrypto:::hash_string_key("test", 65))
})
