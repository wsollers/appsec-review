function(app_warnings target)
  target_compile_options(${target} PRIVATE -Wall)
endfunction()
