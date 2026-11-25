-- build.lua: apkpack's own build, for sqmake.
--
--   sqmake          build/apkpack and the unit tests' programs
--   sqmake test     the unit tests, then the cross-checks against openssl (and
--                   apksigner, keytool and Python's cryptography where they
--                   are installed) and the link checks
--   sqmake --debug  -O0 (build/debug)
--
-- The compiler is $CXX (and $CC): clang and libc++ 23 with `import std;`.
-- Offline: micro-ecc is vendored in third_party/micro-ecc.

local opt = mode.debug and {"-O0", "-g"} or {"-O2", "-g"}
toolchain.cxxflags = {"-std=c++23", "-stdlib=libc++", opt}
toolchain.cflags = {opt}
toolchain.ldflags = {"-stdlib=libc++"}

local warn = {"-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wno-sign-conversion",
              "-Wno-missing-field-initializers"}
-- micro-ecc with only the curve APK signing uses (P-256).
local uecc = {"-DuECC_SUPPORTS_secp160r1=0", "-DuECC_SUPPORTS_secp192r1=0", "-DuECC_SUPPORTS_secp224r1=0",
              "-DuECC_SUPPORTS_secp256r1=1", "-DuECC_SUPPORTS_secp256k1=0"}

-- micro-ecc's own code, without apkpack's warnings (as it is written).
local ecc = library{name = "uecc", srcs = {"third_party/micro-ecc/uECC.c"}, flags = uecc}
local core = library{name = "apkpack_core", srcs = glob("src/*.cppm"), deps = {ecc},
                     flags = {warn, uecc, "-Ithird_party/micro-ecc", "-Isrc"}}

local bin = exe{name = "apkpack", srcs = {"tools/apkpack.cpp"}, deps = {core}, flags = warn}

local tests = {}
for _, src in ipairs(glob("tests/test_*.cpp")) do
  tests[#tests + 1] = exe{name = src:match("([^/]+)%.cpp$"), srcs = {src}, deps = {core}, flags = warn}
end

verb("test", {needs = {bin, tests}, call = function()
  for _, t in ipairs(tests) do
    if exec{t} ~= 0 then return 1 end
  end
  print("all tests passed")
  if exec{"bash", "tests/cross_check.sh", bin} ~= 0 then return 1 end
  return exec{"bash", "tests/link_check.sh", bin}
end})
