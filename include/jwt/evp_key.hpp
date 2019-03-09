#pragma once
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "jwt/exceptions.hpp"
#include "jwt/string_view.hpp"
#include "jwt/error_codes.hpp"
#include <iostream>


#if  OPENSSL_VERSION_NUMBER < 0x10100000L
// provide OpenSSL 1.1.0+ APIs for OpenSSL 1.0.2. 
inline void EVP_PKEY_up_ref(EVP_PKEY* pkey) 
{
  CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
}

inline EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
  if (pkey->type != EVP_PKEY_EC) {
      return nullptr;
  }
  return pkey->pkey.ec;
}
#endif

namespace jwt {

/**
 */
template <typename T, typename Deleter>
std::unique_ptr<T, Deleter> make_unique_ptr(T* ptr, Deleter deleter) 
{
   return std::unique_ptr<T, Deleter>(ptr, deleter);
}

struct pub_pem_str
{
  string_view value;
};

struct priv_pem_str
{
  string_view value;
};

struct pub_pem_file 
{
  const char* filename;
};

struct priv_pem_file 
{
  const char* filename;
};

inline EVP_PKEY* 
to_evp_pkey(pub_pem_str from) noexcept 
{
  auto bufkey = make_unique_ptr(
    BIO_new_mem_buf((void*)from.value.data(), static_cast<int>(from.value.length())), BIO_free_all);
  return PEM_read_bio_PUBKEY(bufkey.get(), nullptr, nullptr, nullptr);
}

inline EVP_PKEY* 
to_evp_pkey(priv_pem_str from) noexcept 
{
  auto bufkey = make_unique_ptr(
    BIO_new_mem_buf((void*)from.value.data(), static_cast<int>(from.value.length())), BIO_free_all);
  return PEM_read_bio_PrivateKey(bufkey.get(), nullptr, nullptr, nullptr);
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
inline EVP_PKEY* 
to_evp_pkey(pub_pem_file from) noexcept 
{
  auto fp = make_unique_ptr(fopen(from.filename, "rb"), fclose);
  return PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr);
}

inline EVP_PKEY* 
to_evp_pkey(priv_pem_file from) noexcept 
{
  auto fp = make_unique_ptr(fopen(from.filename, "rb"), fclose);
  return PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr);
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

/**
 * A Wrapper class for OpenSSL @a EVP_PKEY*. It supports the reference counting mechanism used by OpenSSL.   
 */

class evp_key 
{
public:
  evp_key() = default;

  /**
   * Construct an evp_key from a type T where the expression @a to_evp_pkey(T())  returns 
   * an existing OpenSSL @a EVP_PKEY pointer.
   *
   * Notice it would take over the ownership of the pointer return by @a to_evp_pkey(T()); 
   * i.e., it would NOT increment the reference count of returned pointer during the construction
   * of the object and the reference count of returned pointer would be decemented when the
   * object is destructed.
   */
  template <typename T>
  explicit evp_key(T&& keygen) noexcept(noexcept(to_evp_pkey( std::forward<T>(keygen) )))
  : pkey_(to_evp_pkey(std::forward<T>(keygen)))
  {
  } 

  /**
   * Contruct an evp_key object with an existing OpenSSL @a EVP_PKEY pointer.
   *
   * Notice it would take over the ownership of @a pkey; i.e., it would
   * NOT increment the reference count of @a pkey during the construction
   * of the object and the reference count of @a pkey would be decemented
   * when the object is destructed.
   */
  explicit evp_key(EVP_PKEY* pkey) noexcept
  : pkey_(pkey)
  {
  }

  ~evp_key() noexcept 
  {
    EVP_PKEY_free(pkey_);
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
    evp_key tmp(other);
    swap(tmp, *this);
    return *this;
  }

  evp_key& operator = (evp_key&& other) noexcept 
  {
    evp_key tmp(std::move(other));
    swap(tmp, *this);
    return *this;
  }

  int id() const noexcept { return EVP_PKEY_id(pkey_); }

  EVP_PKEY* get() const noexcept 
  {
    return pkey_;
  }

/**
   * Assign an existing OpenSSL EVP_PKEY pointer to the object.
   *
   * Notice it would take over the ownership of @a pkey; i.e., it would
   * NOT increment the reference count of @a pkey during the construction
   * of the object and the reference count of @a pkey would be decemented
   * when the object is destructed.
   */
  void assign(EVP_PKEY* pkey) noexcept 
  {
    if (pkey_) EVP_PKEY_free(pkey_);
    pkey_ = pkey;
  }

  template <typename T>
  void assign(T&& keygen) noexcept(noexcept(to_evp_pkey( std::forward<T>(keygen) )))
  {
    this->assign(to_evp_pkey(std::forward<T>(keygen)));
  } 

  template <typename T>
  evp_key& operator = (T&& keygen) noexcept(noexcept(to_evp_pkey( std::forward<T>(keygen) )))
  {
    this->assign(std::forward<T>(keygen));
    return *this;
  } 

  EC_KEY* ec_key() const noexcept 
  {
    return pkey_ ? EVP_PKEY_get0_EC_KEY(pkey_) : 0;
  }

  bool empty() const { return pkey_ == nullptr; };
  operator bool() const { return pkey_; }

  friend void swap(evp_key& lhs, evp_key& rhs) noexcept
  {
    std::swap(lhs.pkey_, rhs.pkey_);
  }
private:
  EVP_PKEY* pkey_ = nullptr;
};


} // namespace jwt