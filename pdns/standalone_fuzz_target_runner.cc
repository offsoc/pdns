#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <vector>
#include <cstring>
#include <limits.h>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

int main(int argc, char** argv)
{
  std::cerr<<"StandaloneFuzzTargetMain: running "<<(argc-1)<<" inputs"<<std::endl;

  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  // Define base directory for safe file access
  const char* baseDir = "./inputs/";
  char baseResolved[PATH_MAX];
  if (realpath(baseDir, baseResolved) == nullptr) {
    std::cerr << "Could not resolve base directory: " << baseDir << std::endl;
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    // Concatenate base dir and user input
    char candidatePath[PATH_MAX];
    snprintf(candidatePath, sizeof(candidatePath), "%s%s", baseDir, argv[i]);
    char* resolvedPath = realpath(candidatePath, nullptr);
    if (resolvedPath == nullptr) {
      std::cerr << "Skipping file (could not resolve path): " << std::string(argv[i]) << std::endl;
      continue;
    }
    // Ensure resolved path is within base directory
    size_t baseLen = std::strlen(baseResolved);
    if (strncmp(baseResolved, resolvedPath, baseLen) != 0 || (resolvedPath[baseLen] != '/' && resolvedPath[baseLen] != '\0')) {
      std::cerr << "Skipping file (outside of base directory): " << std::string(argv[i]) << std::endl;
      free(resolvedPath);
      continue;
    }

    struct stat st;
    if (stat(resolvedPath, &st) || !S_ISREG(st.st_mode)) {
      std::cerr<<"Skipping non-regular file: "<<std::string(argv[i])<<std::endl;
      free(resolvedPath);
      continue;
    }

    std::cerr<<"Running: "<<std::string(argv[i])<<std::endl;

    std::ifstream file(resolvedPath, std::ios::binary);
    free(resolvedPath);
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer;
    buffer.resize(fileSize);

    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    if (file.fail()) {
      file.close();
      throw std::runtime_error("Error reading fuzzing input from file '" + std::string(argv[i]) + '"');
    }

    file.close();

    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(buffer.data()), fileSize);

    std::cerr<<"Done: '"<<std::string(argv[i])<<"': ("<<fileSize<<" bytes)"<<std::endl;
  }

  return 0;
}
