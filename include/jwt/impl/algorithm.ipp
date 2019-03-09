/*
Copyright (c) 2017 Arun Muralidharan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#ifndef CPP_JWT_ALGORITHM_IPP
#define CPP_JWT_ALGORITHM_IPP

#if  OPENSSL_VERSION_NUMBER < 0x10100000L
// provide OpenSSL 1.1.0+ APIs for OpenSSL 1.0.2. 
inline EVP_MD_CTX * EVP_MD_CTX_new() 
{
  return EVP_MD_CTX_create();
}

inline void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
  EVP_MD_CTX_destroy(ctx);
}
#endif


namespace jwt {

template <typename Hasher>
verify_result_t HMACSign<Hasher>::verify(
    const jwt::string_view key,
    const jwt::string_view head,
    const jwt::string_view jwt_sign) const
{
  std::error_code ec{};

  auto b64 = make_unique_ptr(BIO_new(BIO_f_base64()), BIO_free_all);
  if (!b64) {
    throw MemoryAllocationException("BIO_new failed");
  }

  BIO* bmem = BIO_new(BIO_s_mem());
  if (!bmem) {
    throw MemoryAllocationException("BIO_new failed");
  }

  BIO_push(b64.get(), bmem);
  BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

  unsigned char enc_buf[EVP_MAX_MD_SIZE];
  uint32_t enc_buf_len = 0;

  unsigned char* res = HMAC(Hasher{}(),
                            key.data(),
                            static_cast<int>(key.length()),
                            reinterpret_cast<const unsigned char*>(head.data()),
                            head.length(),
                            enc_buf,
                            &enc_buf_len);
  if (!res) {
    ec = AlgorithmErrc::VerificationErr;
    return {false, ec};
  }

  BIO_write(b64.get(), enc_buf, enc_buf_len);
  (void)BIO_flush(b64.get());

  int len = BIO_pending(bmem);
  if (len < 0) {
    ec = AlgorithmErrc::VerificationErr;
    return {false, ec};
  }

  std::string cbuf;
  cbuf.resize(len + 1);

  len = BIO_read(bmem, &cbuf[0], len);
  cbuf.resize(len);

  //Make the base64 string url safe
  auto new_len = jwt::base64_uri_encode(&cbuf[0], cbuf.length());
  cbuf.resize(new_len);

  bool ret = (jwt::string_view{cbuf} == jwt_sign);

  return { ret, ec };
}


inline sign_result_t 
UNKNSign::sign(jwt::string_view key, jwt::string_view data) const
{
  switch (alg_) {
  case algorithm::HS256:
    return HMACSign<algo::HS256>().sign(key, data);
  case algorithm::HS384:
    return  HMACSign<algo::HS384>().sign(key, data);
  case algorithm::HS512:
    return  HMACSign<algo::HS512>().sign(key, data);
  case algorithm::NONE:
    return HMACSign<algo::NONE>().sign(key, data);
  case algorithm::RS256:
    return PEMSign<algo::RS256>().sign(key, data);
  case algorithm::RS384:
    return PEMSign<algo::RS384>().sign(key, data);
  case algorithm::RS512:
    return PEMSign<algo::RS512>().sign(key, data);
  case algorithm::ES256:
  case algorithm::ES256K:
    return PEMSign<algo::ES256>().sign(key, data);
  case algorithm::ES384:
    return PEMSign<algo::ES384>().sign(key, data);
  case algorithm::ES512:
    return PEMSign<algo::ES512>().sign(key, data);
  default:
    assert (0 && "Code not reached");
  };
  __builtin_unreachable();
}

inline sign_result_t 
UNKNSign::sign(const jwt::evp_key& key, jwt::string_view data) const
{
  switch (alg_) {
  case algorithm::HS256:
  case algorithm::HS384:
  case algorithm::HS512:
  case algorithm::NONE:
    return { std::string{}, std::error_code{AlgorithmErrc::SigningErr} };
  case algorithm::RS256:
    return PEMSign<algo::RS256>().sign(key, data);
  case algorithm::RS384:
    return PEMSign<algo::RS384>().sign(key, data);
  case algorithm::RS512:
    return PEMSign<algo::RS512>().sign(key, data);
  case algorithm::ES256:
  case algorithm::ES256K:
    return PEMSign<algo::ES256>().sign(key, data);
  case algorithm::ES384:
    return PEMSign<algo::ES384>().sign(key, data);
  case algorithm::ES512:
    return PEMSign<algo::ES512>().sign(key, data);
  default:
    assert (0 && "Code not reached");
  };
  __builtin_unreachable();
}

inline verify_result_t
UNKNSign::verify(jwt::string_view key, jwt::string_view head, jwt::string_view sign) const
{
  switch (alg_) {
  case algorithm::HS256:
    return HMACSign<algo::HS256>().verify(key, head, sign);
  case algorithm::HS384:
    return HMACSign<algo::HS384>().verify(key, head, sign);
  case algorithm::HS512:
    return HMACSign<algo::HS512>().verify(key, head, sign);
  case algorithm::NONE:
    return HMACSign<algo::NONE>().verify(key, head, sign);
  case algorithm::RS256:
    return PEMSign<algo::RS256>().verify(key, head, sign);
  case algorithm::RS384:
    return PEMSign<algo::RS384>().verify(key, head, sign);
  case algorithm::RS512:
    return  PEMSign<algo::RS512>().verify(key, head, sign);
  case algorithm::ES256:
  case algorithm::ES256K:
    return  PEMSign<algo::ES256>().verify(key, head, sign);  
  case algorithm::ES384:
    return PEMSign<algo::ES384>().verify(key, head, sign);
  case algorithm::ES512:
    return PEMSign<algo::ES512>().verify(key, head, sign);
  default:
    __builtin_unreachable();
    assert (0 && "Code not reached");
  };
  return {false, std::error_code{}};
}

inline verify_result_t
UNKNSign::verify(const evp_key& key, jwt::string_view head, jwt::string_view sign) const
{
  switch (alg_) {
  case algorithm::HS256:
  case algorithm::HS384:
  case algorithm::HS512:
  case algorithm::NONE:
    return { false, std::error_code{AlgorithmErrc::VerificationErr} };
  case algorithm::RS256:
    return PEMSign<algo::RS256>().verify(key, head, sign);
  case algorithm::RS384:
    return PEMSign<algo::RS384>().verify(key, head, sign);
  case algorithm::RS512:
    return  PEMSign<algo::RS512>().verify(key, head, sign);
  case algorithm::ES256:
  case algorithm::ES256K:
    return  PEMSign<algo::ES256>().verify(key, head, sign);
  case algorithm::ES384:
    return PEMSign<algo::ES384>().verify(key, head, sign);
  case algorithm::ES512:
    return PEMSign<algo::ES512>().verify(key, head, sign);
  default:
    __builtin_unreachable();
    assert (0 && "Code not reached");
  };
  return {false, std::error_code{}};
}


template <typename Hasher>
verify_result_t PEMSign<Hasher>::verify(
    const jwt::string_view key,
    const jwt::string_view head,
    const jwt::string_view jwt_sign) const
{
  return verify(evp_key(pub_pem_str{key}), head, jwt_sign);
}

template <typename Hasher>
verify_result_t PEMSign<Hasher>::verify(
    const evp_key& pkey,
    const jwt::string_view head,
    const jwt::string_view jwt_sign) const
{
  std::error_code ec{};
  std::string dec_sig = base64_uri_decode(jwt_sign.data(), jwt_sign.length());

  if (!pkey.get()) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  if (pkey.id() != Hasher::type) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  //Convert EC signature back to ASN1
  if (Hasher::type == EVP_PKEY_EC) {
    auto ec_sig = make_unique_ptr(ECDSA_SIG_new(), ECDSA_SIG_free);
    if (!ec_sig) {
      throw MemoryAllocationException("ECDSA_SIG_new failed");
    }

    unsigned int degree = EC_GROUP_get_degree(
        EC_KEY_get0_group(pkey.ec_key()));
    
    unsigned int bn_len = (degree + 7) / 8;

    if ((bn_len * 2) != dec_sig.length()) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }

    BIGNUM* ec_sig_r = BN_bin2bn((unsigned char*)dec_sig.data(), bn_len, nullptr);
    BIGNUM* ec_sig_s = BN_bin2bn((unsigned char*)dec_sig.data() + bn_len, bn_len, nullptr);

    if (!ec_sig_r || !ec_sig_s) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }

    ECDSA_SIG_set0(ec_sig.get(), ec_sig_r, ec_sig_s);

    size_t nlen = i2d_ECDSA_SIG(ec_sig.get(), nullptr);
    dec_sig.resize(nlen);

    auto data = reinterpret_cast<unsigned char*>(&dec_sig[0]);
    nlen = i2d_ECDSA_SIG(ec_sig.get(), &data);

    if (nlen == 0) {
      ec = AlgorithmErrc::VerificationErr;
      return { false, ec };
    }
  }

  auto mdctx_ptr = make_unique_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdctx_ptr) {
    throw MemoryAllocationException("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestVerifyInit(
        mdctx_ptr.get(), nullptr, Hasher{}(), nullptr, pkey.get()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  if (EVP_DigestVerifyUpdate(mdctx_ptr.get(), head.data(), head.length()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  if (EVP_DigestVerifyFinal(
        mdctx_ptr.get(), (unsigned char*)&dec_sig[0], dec_sig.length()) != 1) {
    ec = AlgorithmErrc::VerificationErr;
    return { false, ec };
  }

  return { true, ec };
}

template <typename Hasher>
std::string PEMSign<Hasher>::evp_digest(
    EVP_PKEY* pkey, 
    const jwt::string_view data, 
    std::error_code& ec)
{
  ec.clear();

  auto mdctx_ptr = make_unique_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);

  if (!mdctx_ptr) {
    throw MemoryAllocationException("EVP_MD_CTX_new failed");
  }

  //Initialiaze the digest algorithm
  if (EVP_DigestSignInit(
        mdctx_ptr.get(), nullptr, Hasher{}(), nullptr, pkey) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  //Update the digest with the input data
  if (EVP_DigestSignUpdate(mdctx_ptr.get(), data.data(), data.length()) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  size_t len = 0;

  if (EVP_DigestSignFinal(mdctx_ptr.get(), nullptr, &len) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  std::string sign;
  sign.resize(len);

  //Get the signature
  if (EVP_DigestSignFinal(mdctx_ptr.get(), (unsigned char*)&sign[0], &len) != 1) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  return sign;
}

template <typename Hasher>
std::string PEMSign<Hasher>::public_key_ser(
    const evp_key& pkey, 
    jwt::string_view sign, 
    std::error_code& ec)
{
  // Get the EC_KEY representing a public key and
  // (optionaly) an associated private key
  std::string new_sign;
  ec.clear();

  auto ec_key = pkey.ec_key();

  if (!ec_key) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  uint32_t degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

  auto char_ptr = &sign[0];

  auto ec_sig = make_unique_ptr(d2i_ECDSA_SIG(nullptr,
                                   (const unsigned char**)&char_ptr,
                                   static_cast<long>(sign.length())),
                     ECDSA_SIG_free);

  if (!ec_sig) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  const BIGNUM* ec_sig_r = nullptr;
  const BIGNUM* ec_sig_s = nullptr;

  ECDSA_SIG_get0(ec_sig.get(), &ec_sig_r, &ec_sig_s);

  int r_len = BN_num_bytes(ec_sig_r);
  int s_len = BN_num_bytes(ec_sig_s);
  int bn_len = static_cast<int>((degree + 7) / 8);

  if ((r_len > bn_len) || (s_len > bn_len)) {
    ec = AlgorithmErrc::SigningErr;
    return {};
  }

  auto buf_len = 2 * bn_len;
  new_sign.resize(buf_len);

  BN_bn2bin(ec_sig_r, (unsigned char*)&new_sign[0] + bn_len - r_len);
  BN_bn2bin(ec_sig_s, (unsigned char*)&new_sign[0] + buf_len - s_len);

  return new_sign;
}

} // END namespace jwt

#endif
