library(testthat)
library(flureeCrypto)

# -----------------------------------------------------------------------------
context("encodings.R")
# -----------------------------------------------------------------------------

test_that("pad_hex", {
  even <- "7c06d06ba00f100b0d99c751897ab4ab"
  odd <- "7c06d06ba00f100b0d99c751897ab4a"
  
  even <- pad_hex(even)
  odd <- pad_hex(odd)
  
  expect_equal(even, "7c06d06ba00f100b0d99c751897ab4ab")
  expect_equal(odd, "07c06d06ba00f100b0d99c751897ab4a")
})

test_that("biginteger_to_hex", {
  b <- as.bigz(97)
  result <- biginteger_to_hex(b)
  
  expect_equal(result, "61")
})


test_that("pad_to_length", {
  s <- "hellothere"
  result <- pad_to_length(s, 20)
  
  expect_equal(result, "0000000000hellothere")
})