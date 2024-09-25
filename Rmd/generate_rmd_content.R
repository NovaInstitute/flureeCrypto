
#' generate_rmd_content
#'
#' @param dir_path A character string representing the path to a directory
#'
#' @return A character string with Rmd code representing the content of the directory
#' @export
#'
#' @examples
#' repo_dir <- "path/to/cloned/repo
#' rmd_content <- generate_rmd_content(repo_dir)

generate_rmd_content <- function(dir_path) {
  files <- list.files(dir_path, full.names = TRUE)  # Include full paths
  content <- ""

  for (file in files) {
    if (dir.exists(file)) {  # Check for directories before files
      content <- paste0(content, "# ", basename(file), "\n")
      content <- paste0(content, generate_rmd_content(file))
    } else {
      # Check for supported file extensions (e.g., .R, .py, .txt, .cljc)
      if (grepl("\\.(R|py|txt|cljc)$", basename(file))) {
        content <- paste0(content, "## ", basename(file), "\n")
        code <- readLines(file, encoding = "UTF-8")  # Specify encoding
        content <- paste0(content, "\n", paste("\t", code, collapse = "\n"), "\n\n")
      } else {
        # Handle other file types or skip them
        # ...
      }
    }
  }

  content
}
