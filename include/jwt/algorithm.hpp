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

#ifndef CPP_JWT_ALGORITHM_HPP
#define CPP_JWT_ALGORITHM_HPP

/*!
 * Most of the signing and verification code has been taken
 * and modified for C++ specific use from the C implementation
 * JWT library, libjwt.
 * https://github.com/benmcollins/libjwt/tree/master/libjwt
 */

#include <cassert>
#include <memory>
#include <system_error>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/buffer.h>
#include <openssl/opensslv.h>

#include "jwt/evp_key.hpp"
#include "jwt/base64.hpp"
#include "jwt/config.hpp"

namespace jwt {

/// The result type of the signing function
using sign_result_t = std::pair<std::string, std::error_code>;
/// The result type of verification function
using verify_result_t = std::pair<bool, std::error_code>;

// forward declaration
template <typename Hasher>
struct HMACSign;

template <typename Hasher>
struct PEMSign;

struct UNKNSign;
                                          
/**
 * JWT signing algorithm types.
 */
enum class algorithm
{
  NONE = 0,
  HS256,
  HS384,
  HS512,
  RS256,
  RS384,
  RS512,
  ES256,
  ES384,
  ES512,
  UNKN,
  TERM,
};

namespace algo {

//Me: TODO: All these can be done using code generaion.
//Me: NO. NEVER. I hate Macros.
//Me: You can use templates too.
//Me: No. I would rather prefer explicit.
//Me: Ok. You win.
//Me: Same to you.

/**
 * HS256 algorithm.
 */
struct HS256
{
  typedef HMACSign<HS256> signer;
  static constexpr auto alg = algorithm::HS256;
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/**
 * HS384 algorithm.
 */
struct HS384
{
  typedef HMACSign<HS384> signer;
  static constexpr auto alg = algorithm::HS384;
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/**
 * HS512 algorithm.
 */
struct HS512
{
  typedef HMACSign<HS512> signer;
  static constexpr auto alg = algorithm::HS512;
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

/**
 * NONE algorithm.
 */
struct NONE
{
  typedef HMACSign<NONE> signer;
  static constexpr auto alg = algorithm::NONE;
  void operator()() noexcept
  {
    return;
  }
};

/**
 * RS256 algorithm.
 */
struct RS256
{
  static constexpr int type = EVP_PKEY_RSA;
  typedef PEMSign<RS256> signer;
  static constexpr auto alg = algorithm::RS256;
  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/**
 * RS384 algorithm.
 */
struct RS384
{
  static constexpr int type = EVP_PKEY_RSA;
  typedef PEMSign<RS384> signer;
  static constexpr auto alg = algorithm::RS384;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/**
 * RS512 algorithm.
 */
struct RS512
{
  static constexpr int type = EVP_PKEY_RSA;
  typedef PEMSign<RS512> signer;
  static constexpr auto alg = algorithm::RS512;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

/**
 * ES256 algorithm.
 */
struct ES256
{
  static constexpr int type = EVP_PKEY_EC;
  typedef PEMSign<ES256> signer;
  static constexpr auto alg = algorithm::ES256;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha256();
  }
};

/**
 * ES384 algorithm.
 */
struct ES384
{
  static constexpr int type = EVP_PKEY_EC;
  typedef PEMSign<ES384> signer;
  static constexpr auto alg = algorithm::ES384;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha384();
  }
};

/**
 * ES512 algorithm.
 */
struct ES512
{
  static constexpr int type = EVP_PKEY_EC;
  typedef PEMSign<ES512> signer;
  static constexpr auto alg = algorithm::ES512;

  const EVP_MD* operator()() noexcept
  {
    return EVP_sha512();
  }
};

struct UNKN
{
  typedef UNKNSign signer;
  static constexpr auto alg = algorithm::UNKN;
};
} //END Namespace algo




/**
 * Convert the algorithm enum class type to
 * its stringified form.
 */
inline jwt::string_view alg_to_str(SCOPED_ENUM algorithm alg) noexcept
{
  switch (alg) {
    case algorithm::HS256: return "HS256";
    case algorithm::HS384: return "HS384";
    case algorithm::HS512: return "HS512";
    case algorithm::RS256: return "RS256";
    case algorithm::RS384: return "RS384";
    case algorithm::RS512: return "RS512";
    case algorithm::ES256: return "ES256";
    case algorithm::ES384: return "ES384";
    case algorithm::ES512: return "ES512";
    case algorithm::TERM:  return "TERM";
    case algorithm::NONE:  return "NONE";
    case algorithm::UNKN:  return "UNKN";
    default:               assert (0 && "Unknown Algorithm");
  };
  return "UNKN";
  assert (0 && "Code not reached");
}

/**
 * Convert stringified algorithm to enum class.
 * The string comparison is case insesitive.
 */
inline SCOPED_ENUM algorithm str_to_alg(const jwt::string_view alg) noexcept
{
  if (!alg.length()) return algorithm::NONE;

  if (!strcasecmp(alg.data(), "none"))  return algorithm::NONE;
  if (!strcasecmp(alg.data(), "hs256")) return algorithm::HS256;
  if (!strcasecmp(alg.data(), "hs384")) return algorithm::HS384;
  if (!strcasecmp(alg.data(), "hs512")) return algorithm::HS512;
  if (!strcasecmp(alg.data(), "rs256")) return algorithm::RS256;
  if (!strcasecmp(alg.data(), "rs384")) return algorithm::RS384;
  if (!strcasecmp(alg.data(), "rs512")) return algorithm::RS512;
  if (!strcasecmp(alg.data(), "es256")) return algorithm::ES256;
  if (!strcasecmp(alg.data(), "es384")) return algorithm::ES384;
  if (!strcasecmp(alg.data(), "es512")) return algorithm::ES512;

  return algorithm::UNKN;

  assert (0 && "Code not reached");
}


/**
 */
inline void evp_md_ctx_deletor(EVP_MD_CTX* ptr)
{
  if (ptr) EVP_MD_CTX_destroy(ptr);
}


/**
 */
inline void ec_sig_deletor(ECDSA_SIG* ptr)
{
  if (ptr) ECDSA_SIG_free(ptr);
}

/// Useful typedefs


using evp_mdctx_deletor_t = decltype(&evp_md_ctx_deletor);
using EVP_MDCTX_uptr = std::unique_ptr<EVP_MD_CTX, evp_mdctx_deletor_t>;

using ecsig_deletor_t = decltype(&ec_sig_deletor);
using EC_SIG_uptr = std::unique_ptr<ECDSA_SIG, ecsig_deletor_t>;




/**
 * OpenSSL HMAC based signature and verfication.
 *
 * The template type `Hasher` takes the type representing
 * the HMAC algorithm type from the `jwt::algo` namespace.
 *
 * The struct is specialized for NONE algorithm. See the
 * details of that class as well.
 */
template <typename Hasher>
struct HMACSign
{
  /// The type of Hashing algorithm
  using hasher_type = Hasher;

  HMACSign(SCOPED_ENUM algorithm){}
  HMACSign() = default;
  /**
   * Signs the input using the HMAC algorithm using the
   * provided key.
   *
   * Arguments:
   *  @key : The secret/key to use for the signing.
   *         Cannot be empty string.
   *  @data : The data to be signed.
   *
   *  Exceptions:
   *    Any allocation failure will result in jwt::MemoryAllocationException
   *    being thrown.
   */
  sign_result_t sign(const jwt::string_view key, const jwt::string_view data) const
  {
    if (key.empty()) return { std::string{}, std::error_code{AlgorithmErrc::KeyNotFoundErr} };

    std::string sign;
    sign.resize(EVP_MAX_MD_SIZE);
    std::error_code ec{};

    uint32_t len = 0;

    unsigned char* res = HMAC(Hasher{}(),
                              key.data(),
                              static_cast<int>(key.length()),
                              reinterpret_cast<const unsigned char*>(data.data()),
                              data.length(),
                              reinterpret_cast<unsigned char*>(&sign[0]),
                              &len);
    if (!res) {
      ec = AlgorithmErrc::SigningErr;
    }

    sign.resize(len);
    return { std::move(sign), ec };
  }

  /**
   * Verifies the JWT string against the signature using
   * the provided key.
   *
   * Arguments:
   *  @key : The secret/key to use for the signing.
   *         Cannot be empty string.
   *  @head : The part of JWT encoded string representing header
   *          and the payload claims.
   *  @sign : The signature part of the JWT encoded string.
   *
   *  Returns:
   *    verify_result_t
   *    verify_result_t::first set to true if verification succeeds.
   *    false otherwise. 
   *    verify_result_t::second set to relevant error if verification fails.
   *
   *  Exceptions:
   *    Any allocation failure will result in jwt::MemoryAllocationException
   *    being thrown.
   */
  verify_result_t 
  verify(const jwt::string_view key, const jwt::string_view head, const jwt::string_view sign) const;
};

/**
 * Specialization of `HMACSign` class
 * for NONE algorithm.
 *
 * This specialization is selected for even
 * PEM based algorithms.
 *
 * The signing and verification APIs are
 * basically no-op except that they would 
 * set the relevant error code.
 *
 * NOTE: error_code would be set in the case 
 * of usage of NONE algorithm.
 * Users of this API are expected to check for
 * the case explicitly.
 */
template <>
struct HMACSign<algo::NONE>
{
  using hasher_type = algo::NONE;
  HMACSign(SCOPED_ENUM algorithm){}
  HMACSign() = default;

  /**
   * Basically a no-op. Sets the error code to NoneAlgorithmUsed.
   */
  sign_result_t sign(const jwt::string_view key, const jwt::string_view data) const
  {
    (void)key;
    (void)data;
    std::error_code ec{};
    ec = AlgorithmErrc::NoneAlgorithmUsed;

    return { std::string{}, ec };
  }

  /**
   * Basically a no-op. Sets the error code to NoneAlgorithmUsed.
   */
  verify_result_t
  verify(const jwt::string_view key, const jwt::string_view head, const jwt::string_view sign) const
  {
    (void)key;
    (void)head;
    (void)sign;
    std::error_code ec{};
    ec = AlgorithmErrc::NoneAlgorithmUsed;

    return { true, ec };
  }

};

/**
 * Use for OpenSSL signature and verfication when
 * the algorithm is only known at run time.
 *
 * The signing and verification APIs would be
 * dispatched to HMACSign or PEMSign based on 
 * the `alg` specified in the contructor.
 *
 */
struct UNKNSign
{
  using hasher_type = algo::UNKN;
  UNKNSign(SCOPED_ENUM algorithm alg): alg_(alg){}

  sign_result_t sign(jwt::string_view key, jwt::string_view data) const;
  sign_result_t sign(const jwt::evp_privkey& key, jwt::string_view data) const;

  /**
   */
  verify_result_t verify(jwt::string_view key, jwt::string_view head, jwt::string_view sign) const;
  verify_result_t verify(const jwt::evp_pubkey& key, jwt::string_view head, jwt::string_view sign) const;

  algorithm alg_;
};


/**
 * OpenSSL PEM based signature and verfication.
 *
 * The template type `Hasher` takes the type representing
 * the PEM algorithm type from the `jwt::algo` namespace.
 *
 * For NONE algorithm, HMACSign<> specialization is used.
 * See that for more details.
 */
template <typename Hasher>
struct PEMSign
{
public:
  /// The type of Hashing algorithm
  using hasher_type = Hasher;
  PEMSign(SCOPED_ENUM algorithm){}
  PEMSign() = default;

  /**
   * Signs the input data using PEM encryption algorithm.
   *
   * Arguments:
   *  @key : The key/secret to be used for signing.
   *         Cannot be an empty string.
   *  @data: The data to be signed.
   *
   * Exceptions:
   *  Any allocation failure would be thrown out as
   *  jwt::MemoryAllocationException.
   */
  sign_result_t sign(const jwt::string_view key, const jwt::string_view data) const
  {

    return sign(evp_privkey{pem_str{key}}, data );
  }

  /**
   * Signs the input data using PEM encryption algorithm.
   *
   * Arguments:
   *  @key : The key/secret to be used for signing.
   *         Cannot be an empty string.
   *  @data: The data to be signed.
   *
   * Exceptions:
   *  Any allocation failure would be thrown out as
   *  jwt::MemoryAllocationException.
   */

  sign_result_t sign(const evp_privkey& pkey, const jwt::string_view data) const
  {
    if (pkey.empty()) return { std::string{}, std::error_code{AlgorithmErrc::KeyNotFoundErr} };

    std::error_code ec{};

    std::string ii{data.data(), data.length()};

    //TODO: Use stack string here ?
    std::string sign = evp_digest(pkey.get(), data, ec);

    if (ec) return { std::string{}, ec };

    if (Hasher::type == EVP_PKEY_EC) {
      sign = public_key_ser(pkey, sign, ec);
    }

    return { std::move(sign), ec };
  }

  /**
   * Verifies the JWT string against the signature using
   * the provided key.
   *
   * Arguments:
   *  @key : The secret/key to use for the signing.
   *         Cannot be empty string.
   *  @head : The part of JWT encoded string representing header
   *          and the payload claims.
   *  @sign : The signature part of the JWT encoded string.
   *
   *  Returns:
   *    verify_result_t
   *    verify_result_t::first set to true if verification succeeds.
   *    false otherwise. 
   *    verify_result_t::second set to relevant error if verification fails.
   *
   *  Exceptions:
   *    Any allocation failure will result in jwt::MemoryAllocationException
   *    being thrown.
   */
  verify_result_t
  verify(const jwt::string_view key, const jwt::string_view head, const jwt::string_view sign) const;

  verify_result_t 
  verify(const evp_pubkey& key, const jwt::string_view head, const jwt::string_view sign) const;

private:

  /*!
   */
  static std::string evp_digest(EVP_PKEY* pkey, const jwt::string_view data, std::error_code& ec);

  /*!
   */
  static std::string public_key_ser(const evp_privkey& pkey, jwt::string_view sign, std::error_code& ec);

#if OPENSSL_VERSION_NUMBER < 0x10100000L

  //ATTN: Below 2 functions
  //are Taken from https://github.com/nginnever/zogminer/issues/39

  /**
   */
  static void ECDSA_SIG_get0(const ECDSA_SIG* sig, const BIGNUM** pr, const BIGNUM** ps)
  {
    if (pr != nullptr) *pr = sig->r;
    if (ps != nullptr) *ps = sig->s;
  };

  /**
   */
  static int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s)
  { 
    if (r == nullptr || s == nullptr) return 0;

    BN_clear_free(sig->r);
    BN_clear_free(sig->s);

    sig->r = r;
    sig->s = s;
    return 1;
  }

#endif
};




} // END namespace jwt

#include "jwt/impl/algorithm.ipp"


#endif
