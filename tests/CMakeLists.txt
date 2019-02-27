
include_directories(${OPENSSL_INCLUDE_DIR})

SET(CERT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/certs")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DCERT_ROOT_DIR=\"\\\"${CERT_ROOT_DIR}\\\"\"")

cpp_jwt_target(test_jwt_object test_jwt_object.cc)


cpp_jwt_target(test_jwt_encode test_jwt_encode.cc)


cpp_jwt_target(test_jwt_decode test_jwt_decode.cc)


cpp_jwt_target(test_jwt_decode_verifiy test_jwt_decode_verifiy.cc)


cpp_jwt_target(test_jwt_decode_verifiy_with_exception test_jwt_decode_verifiy_with_exception.cc)


cpp_jwt_target(test_jwt_rsa test_jwt_rsa.cc)


cpp_jwt_target(test_jwt_es test_jwt_es.cc)
