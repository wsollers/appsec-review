# Built inside the SVF-3.3 source tree (svf-llvm/tools/AppsecAliasExport) so it links exactly the
# SvfCore/SvfLLVM libraries and LLVM settings of the pinned SVF build.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_llvm_executable(svf-alias-export svf-alias-export.cpp)
target_link_libraries(svf-alias-export PRIVATE SvfCore SvfLLVM Threads::Threads)
set_target_properties(svf-alias-export PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SVF_BINARY_DIR}/bin)
