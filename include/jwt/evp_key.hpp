#pragma once
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "jwt/exceptions.hpp"
#include "jwt/string_view.hpp"
#include "jwt/error_codes.hpp"
#include <iostream>


#if  OPENSSL_VERSION_NUMBER < 0x10100000L
inline void EVP_PKEY_up_ref(EVP_PKEY* pkey) 
{
  CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
}

inline EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
  return pkey->pkey.ec;
}
#endif

namespace jwt {

/**
 */
inline void bio_deletor(BIO* ptr)
{
  if (ptr) BIO_free_all(ptr);
}

using bio_deletor_t = decltype(&bio_deletor);
using BIO_uptr = std::unique_ptr<BIO, bio_deletor_t>;


struct pem_str 
{
  string_view value;
  operator bool() const { return !value.empty(); }
};

class pem_file 
{
public:
  pem_file(const char* filename) noexcept
  : fp_(fopen(filename, "rb")) {
  }
  ~pem_file() { if (fp_)  { fclose(fp_); } }

  pem_file(const pem_file&) = delete;
  pem_file& operator=(const pem_file&) = delete;
  pem_file(pem_file&& other) noexcept
  : fp_(other.fp_) 
  { 
    other.fp_ = 0;
  }

  FILE* get() const noexcept { return fp_; }
  bool empty() const { return fp_ == nullptr; };
  operator bool() const { return fp_; }
private:
  FILE* fp_=0;
};



struct pem_pubkey_tag 
{
  static EVP_PKEY* read_key(BIO *bp, EVP_PKEY **x,pem_password_cb *cb, void *u) { return PEM_read_bio_PUBKEY(bp, x, cb, u); }
  static EVP_PKEY* read_key(FILE *fp, EVP_PKEY **x,pem_password_cb *cb, void *u) { return PEM_read_PUBKEY(fp, x, cb, u); }
};

struct pem_privatekey_tag 
{
  static EVP_PKEY* read_key(BIO *bp, EVP_PKEY **x,pem_password_cb *cb, void *u) { return PEM_read_bio_PrivateKey(bp, x, cb, u); }
  static EVP_PKEY* read_key(FILE *fp, EVP_PKEY **x,pem_password_cb *cb, void *u) { return PEM_read_PrivateKey(fp, x, cb, u); }
};

template <typename KeyTag>
class evp_key 
{
public:
  evp_key() = default;
  evp_key(pem_str pem_key)
  {
    BIO_uptr bufkey{
      BIO_new_mem_buf((void*)pem_key.value.data(), pem_key.value.length()), bio_deletor};

    if (!bufkey) {
      throw MemoryAllocationException("BIO_new_mem_buf failed");
    }
    pkey_ = KeyTag::read_key(bufkey.get(), nullptr, nullptr, nullptr);
  }

  explicit evp_key(FILE* fp) noexcept
  : pkey_( fp ? KeyTag::read_key(fp, nullptr, nullptr, nullptr) : nullptr) 
  {
  }

  evp_key(pem_file&& keyfile) noexcept
  : evp_key(keyfile.get())
  {
  }

  explicit evp_key(EVP_PKEY* pkey) noexcept
  : pkey_(pkey)
  {
  }

  ~evp_key() noexcept 
  {
    if (pkey_) EVP_PKEY_free(pkey_);
  }

  evp_key(const evp_key& other) noexcept
  : pkey_(other.pkey_) 
  {
    if (pkey_) EVP_PKEY_up_ref(pkey_);
  }

  evp_key(evp_key&& other) noexcept
  : pkey_(other.pkey_) 
  {
    other.pkey_ = nullptr;
  }

  evp_key& operator = (const evp_key& other) noexcept 
  {
    EVP_PKEY* temp = pkey_;
    pkey_ = other.pkey_;
    if (pkey_) EVP_PKEY_up_ref(pkey_);
    if (temp) EVP_PKEY_free(temp);
  }

  int id() const noexcept { return EVP_PKEY_id(pkey_); }

  EVP_PKEY* get() const noexcept 
  {
    return pkey_;
  }

  const ec_key_st* ec_key() const noexcept 
  {
    return pkey_ ? EVP_PKEY_get0_EC_KEY(pkey_) : 0;
  }

  bool empty() const { return pkey_ == nullptr; };
  operator bool() const { return pkey_; }
private:
  EVP_PKEY* pkey_ = nullptr;
};

typedef evp_key<pem_pubkey_tag> evp_pubkey;
typedef evp_key<pem_privatekey_tag> evp_privkey;

} // namespace jwt