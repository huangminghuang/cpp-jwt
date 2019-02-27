

SET(CERT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rsa_256")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DCERT_ROOT_DIR=\"\\\"${CERT_ROOT_DIR}\\\"\"")

cpp_jwt_target(simple_ex1 simple_ex1.cc)

cpp_jwt_target(simple_ex2 simple_ex2.cc)

cpp_jwt_target(simple_ex3_rsa simple_ex3_rsa.cc)
