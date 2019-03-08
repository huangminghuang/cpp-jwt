#include <iostream>
#include <fstream>
#include <map>
#include <chrono>

#include "gtest/gtest.h"
#include "jwt/jwt.hpp"

#define EC384_PUB_KEY CERT_ROOT_DIR "/ec_certs/ec384_pub.pem"
#define EC384_PRIV_KEY CERT_ROOT_DIR "/ec_certs/ec384_priv.pem"

#define EC256K_PUB_KEY CERT_ROOT_DIR "/ec_certs/ec256k_pub.pem"
#define EC256K_PRIV_KEY CERT_ROOT_DIR "/ec_certs/ec256k_priv.pem"

std::string read_from_file(const std::string& path)
{
  std::string contents;
  std::ifstream is{path, std::ifstream::binary};

  if (is) {
    // get length of file:
    is.seekg (0, is.end);
    auto length = is.tellg();
    is.seekg (0, is.beg);
    contents.resize(length);

    is.read(&contents[0], length);
    if (!is) {
      is.close();
      return {};
    }
  }

  is.close();
  return contents;
}

TEST (ESAlgo, ES256EncodingDecodingTest)
{
  using namespace jwt::params;

  std::string key = read_from_file(EC384_PRIV_KEY);
  ASSERT_TRUE (key.length());

  jwt::jwt_object obj{algorithm("ES256"), secret(key)};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 1513862371)
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  EXPECT_FALSE (ec);

  key = read_from_file(EC384_PUB_KEY);
  ASSERT_TRUE (key.length());

  auto dec_obj = jwt::decode(enc_str, algorithms({"es256"}), ec, verify(false), secret(key));
  EXPECT_FALSE (ec);

  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES256);
  EXPECT_TRUE (dec_obj.has_claim("iss"));
  EXPECT_TRUE (dec_obj.has_claim("aud"));
  EXPECT_TRUE (dec_obj.has_claim("exp"));

  EXPECT_FALSE (dec_obj.has_claim("sub"));
}

TEST (ESAlgo, ES384EncodingDecodingTest)
{
  using namespace jwt::params;

  std::string key = read_from_file(EC384_PRIV_KEY);
  ASSERT_TRUE (key.length());

  jwt::jwt_object obj{algorithm("ES384"), secret(key)};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 1513862371)
     ;

  auto enc_str = obj.signature();

  key = read_from_file(EC384_PUB_KEY);
  ASSERT_TRUE (key.length());

  auto dec_obj = jwt::decode(enc_str, algorithms({"es384"}), verify(false), secret(key));

  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES384);
}

TEST (ESAlgo, ES512EncodingDecodingTest)
{
  using namespace jwt::params;

  std::string key = read_from_file(EC384_PRIV_KEY);
  ASSERT_TRUE (key.length());

  jwt::jwt_object obj{algorithm("ES512"), secret(key)};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 1513862371)
     ;

  auto enc_str = obj.signature();

  key = read_from_file(EC384_PUB_KEY);
  ASSERT_TRUE (key.length());

  auto dec_obj = jwt::decode(enc_str, algorithms({"es512"}), verify(false), secret(key));

  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES512);
}

TEST (ESAlgo, ES384EncodingDecodingValidTest)
{
  using namespace jwt::params;

  std::string key = read_from_file(EC384_PRIV_KEY);
  ASSERT_TRUE (key.length());

  jwt::jwt_object obj{algorithm("ES384"), secret(key)};

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 4682665886) // Expires on Sunday, May 22, 2118 12:31:26 PM GMT
     ;

  auto enc_str = obj.signature();

  key = read_from_file(EC384_PUB_KEY);
  ASSERT_TRUE (key.length());

  auto dec_obj = jwt::decode(enc_str, algorithms({"es384"}), verify(true), secret(key));

  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES384);
  EXPECT_TRUE (dec_obj.has_claim("exp"));
  EXPECT_TRUE (obj.payload().has_claim_with_value("exp", 4682665886));

}

TEST (ESAlgo, ES384EncodingDecodingNewApiTest)
{
  using namespace jwt::params;
  std::string pubkey_str = read_from_file(EC384_PUB_KEY);
  std::string privkey_str = read_from_file(EC384_PRIV_KEY);

  jwt::evp_pubkey pubkey = jwt::pem_str{pubkey_str};
  jwt::evp_privkey privkey = jwt::pem_str{privkey_str};

  EXPECT_TRUE(pubkey.get());
  EXPECT_TRUE(privkey.get());

  jwt::jwt_object obj;

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 4682665886) // Expires on Sunday, May 22, 2118 12:31:26 PM GMT
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec, secret<jwt::algo::ES384>(privkey));
  EXPECT_FALSE (ec);
  
  auto dec_obj = jwt::decode(enc_str, ec, verify(true), secret<jwt::algo::ES384>(pubkey));

  EXPECT_FALSE (ec);
  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES384);
  EXPECT_TRUE (dec_obj.has_claim("exp"));
  EXPECT_TRUE (obj.payload().has_claim_with_value("exp", 4682665886));

  auto dec_obj2 = jwt::decode(enc_str, ec, verify(true), secret([&pubkey](const jwt::jwt_object& obj) -> jwt::evp_pubkey { 
    if (obj.header().algo() == jwt::algorithm::ES384 && obj.payload().get_claim_value<std::string>("iss") == "arun.muralidharan") {
      return pubkey;
    }
    return {};
  }));

  EXPECT_FALSE (ec);
  EXPECT_EQ (dec_obj2.header().algo(), jwt::algorithm::ES384);

#if !defined(_WIN64) && !defined(_WIN32)
// using PEM_read_PUBKEY() would trigger "OPENSSL_Uplink(7120B000,08): no OPENSSL_Applink" on windows, skip it for now.
  auto dec_obj3 = jwt::decode(enc_str, ec, verify(true), secret<jwt::algo::ES384>([](const jwt::jwt_object& obj) -> jwt::evp_pubkey { 
    if (obj.payload().get_claim_value<std::string>("iss") == "arun.muralidharan") {
      return jwt::pem_file{EC384_PUB_KEY};
    }
    return {};
  }));

  EXPECT_FALSE (ec);
  EXPECT_EQ (dec_obj3.header().algo(), jwt::algorithm::ES384);
#endif
}

TEST (ESAlgo, ES256KEncodingDecodingNewApiTest) {
  using namespace jwt::params;
  std::string pubkey_str = read_from_file(EC256K_PUB_KEY);
  std::string privkey_str = read_from_file(EC256K_PRIV_KEY);

  jwt::evp_pubkey pubkey = jwt::pem_str{pubkey_str};
  jwt::evp_privkey privkey = jwt::pem_str{privkey_str};

  EXPECT_TRUE(pubkey.get());
  EXPECT_TRUE(privkey.get());

  jwt::jwt_object obj;

  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("aud", "all")
     .add_claim("exp", 4682665886) // Expires on Sunday, May 22, 2118 12:31:26 PM GMT
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec, secret<jwt::algo::ES256K>(privkey));
  EXPECT_FALSE (ec);
  
  auto dec_obj = jwt::decode(enc_str, ec, verify(true), secret<jwt::algo::ES256K>(pubkey));

  EXPECT_FALSE (ec);
  EXPECT_EQ (dec_obj.header().algo(), jwt::algorithm::ES256K);
  EXPECT_TRUE (dec_obj.has_claim("exp"));
  EXPECT_TRUE (obj.payload().has_claim_with_value("exp", 4682665886));
}


int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
