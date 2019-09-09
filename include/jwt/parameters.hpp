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

#ifndef CPP_JWT_PARAMETERS_HPP
#define CPP_JWT_PARAMETERS_HPP

#include <map>
#include <chrono>
#include <string>
#include <vector>
#include <utility>
#include <unordered_map>
#include <functional>

#include "jwt/algorithm.hpp"
#include "jwt/detail/meta.hpp"
#include "jwt/string_view.hpp"

namespace jwt {

using system_time_t = std::chrono::time_point<std::chrono::system_clock>;
namespace params {


namespace detail {
/**
 * Parameter for providing the payload.
 * Takes a Mapping concept representing
 * key-value pairs.
 *
 * NOTE: MappingConcept allows only strings
 * for both keys and values. Use `add_header`
 * API of `jwt_object` otherwise.
 *
 * Modeled as ParameterConcept.
 */
template <typename MappingConcept>
struct payload_param
{
  payload_param(MappingConcept&& mc)
    : payload_(std::forward<MappingConcept>(mc))
  {}

  MappingConcept get() && { return std::move(payload_); }
  const MappingConcept& get() const& { return payload_; }

  MappingConcept payload_;
};




/**
 * Parameter for providing the secret key.
 * It may store a simple an object of type string/string_view or evp_key 
 * containing the secret key or a lambda which takes a jwt_object as parameter
 * to return the secret key based on the content of the jwt_object.

 * Modeled as ParameterConcept.
 */


template <typename Key, typename Hasher = algo::UNKN>
struct secret_param
{
  using hash = Hasher;
  template <typename T, typename U>
  using is_invocable = jwt::detail::meta::is_invocable<T,U>;

  Key get() const { return key_; }
  template <typename U,
            typename std::enable_if_t<!is_invocable<Key, U>::value && std::is_reference<Key>::value, int> = 0>
  Key get( U&&) const { return key_; }

#if !defined(_MSC_VER) || (_MSC_VER >= 1920)
  template <typename U,
            typename std::enable_if_t<!is_invocable<Key, U>::value && !std::is_reference<Key>::value, int> = 0>
  Key get( U&& u) && { return std::move(key_); }
#endif

  template <typename U>
  auto get(U&& u, typename std::enable_if_t<is_invocable<Key, U>::value, int> = 0) const { return key_(u);}

  Key key_;
};
/**
 * Parameter for providing the algorithm to use.
 * The parameter can accept either the string representation
 * or the enum class.
 *
 * Modeled as ParameterConcept.
 */
struct algorithm_param
{
  algorithm_param(const string_view alg)
    : alg_(str_to_alg(alg))
  {}

  algorithm_param(jwt::algorithm alg)
    : alg_(alg)
  {}

  jwt::algorithm get() const noexcept
  {
    return alg_;
  }

  typename jwt::algorithm alg_;
};

/**
 * Parameter for providing additional headers.
 * Takes a mapping concept representing
 * key-value pairs.
 *
 * Modeled as ParameterConcept.
 */
template <typename MappingConcept>
struct headers_param
{
  headers_param(MappingConcept&& mc)
    : headers_(std::forward<MappingConcept>(mc))
  {}

  MappingConcept get() && { return std::move(headers_); }
  const MappingConcept& get() const& { return headers_; }

  MappingConcept headers_;
};

/**
 */
struct verify_param
{
  verify_param(bool v)
    : verify_(v)
  {}

  bool get() const { return verify_; }

  bool verify_;
};

/**
 */
template <typename Sequence>
struct algorithms_param
{
  algorithms_param(Sequence&& seq)
    : seq_(std::forward<Sequence>(seq))
  {}

  Sequence get() && { return std::move(seq_); }
  const Sequence& get() const& { return seq_; }

  Sequence seq_;
};

/**
 */
struct leeway_param
{
  leeway_param(uint32_t v)
    : leeway_(v)
  {}

  uint32_t get() const noexcept { return leeway_; }

  uint32_t leeway_;
};

/**
 */
struct nbf_param
{
  nbf_param(const jwt::system_time_t tp)
    : duration_(std::chrono::duration_cast<
        std::chrono::seconds>(tp.time_since_epoch()).count())
  {}

  nbf_param(const uint64_t epoch)
    : duration_(epoch)
  {}
 
  uint64_t get() const noexcept { return duration_; }

  uint64_t duration_;
};

template <typename T>
struct checker_param
{
  T get() const { return check_; }
  T check_;
};

} // END namespace detail

// Useful typedef
using param_init_list_t = std::initializer_list<std::pair<jwt::string_view, jwt::string_view>>;
using param_seq_list_t  = std::initializer_list<jwt::string_view>;


/**
 */
inline detail::payload_param<std::unordered_map<std::string, std::string>>
payload(const param_init_list_t& kvs)
{
  std::unordered_map<std::string, std::string> m;

  for (const auto& elem : kvs) {
    m.emplace(elem.first.data(), elem.second.data());
  }

  return { std::move(m) };
}

/**
 */
template <typename MappingConcept>
detail::payload_param<MappingConcept>
payload(MappingConcept&& mc)
{
  static_assert (jwt::detail::meta::is_mapping_concept<MappingConcept>::value,
      "Template parameter does not meet the requirements for MappingConcept.");

  return { std::forward<MappingConcept>(mc) };
}


/**
 */
template <typename Key>
inline detail::secret_param<Key> secret(Key&& sv)
{
  return { std::forward<Key>(sv) };
}

template <typename Hash, typename Key>
inline detail::secret_param<Key, Hash> secret(Key&& sv)
{
  return { std::forward<Key>(sv) };
}

/**
 */
inline detail::algorithm_param algorithm(const string_view sv)
{
  return { sv };
}

/**
 */
inline detail::algorithm_param algorithm(jwt::algorithm alg)
{
  return { alg };
}

/**
 */
inline detail::headers_param<std::map<std::string, std::string>>
headers(const param_init_list_t& kvs)
{
  std::map<std::string, std::string> m;

  for (const auto& elem : kvs) {
    m.emplace(elem.first.data(), elem.second.data());
  }

  return { std::move(m) };
}

/**
 */
template <typename MappingConcept>
detail::headers_param<MappingConcept>
headers(MappingConcept&& mc)
{
  static_assert (jwt::detail::meta::is_mapping_concept<MappingConcept>::value,
       "Template parameter does not meet the requirements for MappingConcept.");

  return { std::forward<MappingConcept>(mc) };
}

/**
 */
inline detail::verify_param
verify(bool v)
{
  return { v };
}

/**
 */
inline detail::leeway_param
leeway(uint32_t l)
{
  return { l };
}

/**
 */
inline detail::algorithms_param<std::vector<std::string>>
algorithms(const param_seq_list_t& seq)
{
  std::vector<std::string> vec;
  vec.reserve(seq.size());

  for (const auto& e: seq) { vec.emplace_back(e.data(), e.length()); }

  return { std::move(vec) };
}

template <typename SequenceConcept>
detail::algorithms_param<SequenceConcept>
algorithms(SequenceConcept&& sc)
{
  return { std::forward<SequenceConcept>(sc) };
}

template <typename T>
inline detail::checker_param<T>
custom_check(T&& lambda ) noexcept
{
  return {std::forward<T>(lambda)};
}

/**
 */
inline auto
aud(jwt::string_view value) noexcept
{
  return custom_check([value](const auto& obj) noexcept -> std::error_code {
    //Check for issuer
    if (!obj.payload().has_claim_with_value("aud", value)) {
      return VerificationErrc::InvalidAudience;
    }
    return std::error_code{};
  });
}

/**
 */

inline auto
issuer(jwt::string_view value) noexcept
{
  return custom_check([value](const auto& obj) noexcept -> std::error_code {
    //Check for issuer
    if (!obj.payload().has_claim_with_value("iss", value)) {
      return VerificationErrc::InvalidIssuer;
    }
    return std::error_code{};
  });
}

/**
 */
inline auto
sub(jwt::string_view value) noexcept
{
  return custom_check([value](const auto& obj) noexcept -> std::error_code {
    //Check for issuer
    if (!obj.payload().has_claim_with_value("sub", value)) {
      return VerificationErrc::InvalidSubject;
    }
    return std::error_code{};
  });
}


/**
 */
inline auto
validate_iat(bool v) noexcept
{
  return custom_check([v](const auto& obj) noexcept ->std::error_code {
    if (v) {
      if (!obj.has_claim("iat")) {
        return VerificationErrc::InvalidIAT;
      } else {
        auto val = obj.payload().create_json_obj();
        auto itr = val.find("iat");
        if (! itr->is_number_unsigned()) return VerificationErrc::TypeConversionError;
      }
    } 
    return std::error_code{};
  });
}

/**
 */
inline auto
validate_jti(bool v) noexcept
{
  return custom_check([v](const auto& obj) noexcept -> std::error_code {
    //Check for jti
    if (v && !obj.payload().has_claim("jti")) {
      return VerificationErrc::InvalidJTI;
    }
    return std::error_code{};
  });
}

/**
 */
inline detail::nbf_param
nbf(const system_time_t tp)
{
  return { tp };
}

/**
 */
inline detail::nbf_param
nbf(const uint64_t epoch)
{
  return { epoch };
}


} // END namespace params
} // END namespace jwt

#endif
