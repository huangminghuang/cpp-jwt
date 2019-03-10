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

#ifndef JWT_IPP
#define JWT_IPP

#include "jwt/config.hpp"
#include "jwt/detail/meta.hpp"
#include <algorithm>
#include <iomanip>

namespace jwt {

/**
 */
static inline void jwt_throw_exception(const std::error_code& ec);

template <typename T, typename Cond>
std::string to_json_str(const T& obj, bool pretty)
{
  return pretty ? obj.create_json_obj().dump(2)
                : obj.create_json_obj().dump()
                ;
}


template <typename T>
std::ostream& write(std::ostream& os, const T& obj, bool pretty)
{
  pretty ? (os << std::setw(2) << obj.create_json_obj())
         : (os                 << obj.create_json_obj())
         ;

  return os;
}


template <typename T, typename Cond>
std::ostream& operator<< (std::ostream& os, const T& obj)
{
  os << obj.create_json_obj();
  return os;
}

//========================================================================

inline void jwt_header::decode(const jwt::string_view enc_str, std::error_code& ec)
{
  ec.clear();
  std::string json_str = base64_decode(enc_str);

  
  payload_ = json_t::parse(std::move(json_str), nullptr, false);
  if (payload_.is_discarded()) {
    ec = DecodeErrc::JsonParseError;
    return;
  }

  //Look for the algorithm field
  auto alg_itr = payload_.find(static_cast<const char*>("alg"));
  if (alg_itr == payload_.end()) {
    ec = DecodeErrc::AlgHeaderMiss;
    return;
  }

  alg_ = str_to_alg(alg_itr.value().get<std::string>());

  if (alg_ != algorithm::NONE)
  {
    auto itr = payload_.find(static_cast<const char*>("typ"));

    if (itr != payload_.end()) {
      const auto& typ = itr.value().get<std::string>();
      if (strcasecmp(typ.c_str(), "JWT")) {
        ec = DecodeErrc::TypMismatch;
        return;
      }
    }
  } else {
    //TODO:
  }

  return;
}

inline void jwt_header::decode(const jwt::string_view enc_str)
{
  std::error_code ec;
  decode(enc_str, ec);
  if (ec) {
    throw DecodeError(ec.message());
  }
  return;
}

inline void jwt_payload::decode(const jwt::string_view enc_str, std::error_code& ec)
{
  ec.clear();
  std::string json_str = base64_decode(enc_str);
  payload_ = json_t::parse(std::move(json_str), nullptr, false);
  if (payload_.is_discarded()) {
    ec = DecodeErrc::JsonParseError;
    return;
  }
  return;
}

inline void jwt_payload::decode(const jwt::string_view enc_str)
{
  std::error_code ec;
  decode(enc_str, ec);
  if (ec) {
    throw DecodeError(ec.message());
  }
  return;
}

//==================================================================
namespace detail {

inline verify_result_t verify(const jwt_object& obj, string_view head, string_view sign) 
{
  if (obj.header().algo() != algorithm::NONE) {
    return {false, std::error_code{DecodeErrc::KeyNotPresent}};
  }
  return {true, std::error_code{AlgorithmErrc::NoneAlgorithmUsed}};
}

template<typename Key, typename Hasher, typename ...Rest>
verify_result_t verify(const jwt_object& obj, string_view head, string_view sign, params::detail::secret_param<Key, Hasher>&& sparam, Rest&&...) ;
template<typename T, typename ...Rest>
verify_result_t verify(const jwt_object& obj, string_view head, string_view sign, params::detail::checker_param<T>&& checker, Rest&&... r) ;

template<typename T, typename ...Rest>
verify_result_t verify(const jwt_object& obj, string_view head, string_view sign, T&&, Rest&&... r) 
{
  return verify(obj, head, sign, std::forward<Rest>(r)...);
}

template<typename Key, typename Hasher, typename ...Rest>
verify_result_t verify(const jwt_object& obj, string_view head, string_view sign, params::detail::secret_param<Key, Hasher>&& s, Rest&&... r) 
{
  using signer = typename Hasher::signer;
  verify_result_t result = verify(obj, head, sign, std::forward<Rest>(r)...);
  if (result.second == std::error_code{DecodeErrc::KeyNotPresent})
    return signer{obj.header().algo()}.verify(std::move(s).get(obj), head, sign);
  return result;
}

template<typename T, typename ...Rest>
verify_result_t verify(const jwt_object& obj, string_view head, string_view sign, params::detail::checker_param<T>&& checker, Rest&&... r) 
{
  std::error_code ec = checker.check_(obj);
  if (ec) return { false, ec };
  return verify(obj, head, sign, std::forward<Rest>(r)...);
}


template <typename Key, typename Signer> 
std::string encode(Key&& key,
                   const Signer& signer,                 
                   const jwt_object& obj,
                   std::error_code& ec)
{
  std::string jwt_msg;
  ec.clear();
  //TODO: Optimize allocations

  std::string hdr_sign = obj.header().base64_encode();
  std::string pld_sign = obj.payload().base64_encode();
  std::string data = hdr_sign + '.' + pld_sign;

  auto res = signer.sign(std::forward<Key>(key), data);

  if (res.second && res.second != AlgorithmErrc::NoneAlgorithmUsed) {
    ec = res.second;
    return {};
  }

  std::string b64hash;

  if (!res.second) {
    b64hash = base64_encode(res.first.c_str(), res.first.length());
  }

  auto new_len = base64_uri_encode(&b64hash[0], b64hash.length());
  b64hash.resize(new_len);

  jwt_msg = data + '.' + b64hash;

  return jwt_msg;
}  

}

//==================================================================

//
template <typename First, typename... Rest,
          typename SFINAE_COND>
jwt_object::jwt_object(
    First&& first, Rest&&... rest)
{
  static_assert (detail::meta::is_parameter_concept<First>::value && 
                 detail::meta::are_all_params<Rest...>::value,
      "All constructor argument types must model ParameterConcept");

  set_parameters(std::forward<First>(first), std::forward<Rest>(rest)...);
}

template <typename Map, typename... Rest>
void jwt_object::set_parameters(
    params::detail::payload_param<Map>&& payload, Rest&&... rargs)
{
  for (const auto& elem : payload.get()) {
    payload_.add_claim(std::move(elem.first), std::move(elem.second));
  }
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename Key, typename Hash, typename... Rest>
void jwt_object::set_parameters(
    params::detail::secret_param<Key, Hash>&& secret, Rest&&... rargs)
{
  secret_ = static_cast<std::string>(secret.get(*this));
  if (Hash::alg != algorithm::UNKN) {
    header_.algo(Hash::alg);
  }
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename... Rest>
void jwt_object::set_parameters(
    params::detail::algorithm_param alg, Rest&&... rargs)
{
  header_.algo(alg.get());
  set_parameters(std::forward<Rest>(rargs)...);
}

template <typename Map, typename... Rest>
void jwt_object::set_parameters(
    params::detail::headers_param<Map>&& header, Rest&&... rargs)
{
  for (const auto& elem : header.get()) {
    header_.add_header(std::move(elem.first), std::move(elem.second));
  }

  set_parameters(std::forward<Rest>(rargs)...);
}

inline void jwt_object::set_parameters()
{
  //sentinel call
  return;
}

inline jwt_object& jwt_object::add_claim(const std::string& name, system_time_t tp)
{
  return add_claim(
      name,
      std::chrono::duration_cast<
        std::chrono::seconds>(tp.time_since_epoch()).count()
      );
}

inline jwt_object& jwt_object::remove_claim(const std::string& name)
{
  payload_.remove_claim(name);
  return *this;
}

inline std::string jwt_object::signature(std::error_code& ec) const
{
  return signature(ec, params::secret(secret_));
}

inline std::string jwt_object::signature() const
{
  return signature(params::secret(secret_));
}

template <typename Key> 
inline std::string jwt_object::signature(std::error_code& ec, params::detail::secret_param<Key, algo::UNKN>&& s) const
{
  return detail::encode(std::move(s).get(*this), UNKNSign{header_.algo()}, *this, ec);
}

template <typename Key, typename Hasher> 
inline std::enable_if_t<!std::is_same<Hasher, algo::UNKN>::value, std::string> 

jwt_object::signature(std::error_code& ec, params::detail::secret_param<Key, Hasher>&& s)
{
  header_.algo(Hasher::alg);
  using signer = typename Hasher::signer;
  return detail::encode(std::move(s).get(*this), signer(), *this, ec);
}

template <typename Key> 
inline std::string jwt_object::signature(params::detail::secret_param<Key, algo::UNKN>&& s) const
{
  std::error_code ec;
  std::string res = this->signature(ec, std::forward<params::detail::secret_param<Key, algo::UNKN>>(s));
  if (ec) {
    throw SigningError(ec.message());
  }
  return res;
}

template <typename Key, typename Hasher> 
inline std::enable_if_t<!std::is_same<Hasher, algo::UNKN>::value, std::string>
jwt_object::signature(params::detail::secret_param<Key, Hasher>&& s)
{
  std::error_code ec;
  std::string res = this->signature(ec, std::forward<params::detail::secret_param<Key, Hasher>>(s));
  if (ec) {
    throw SigningError(ec.message());
  }
  return res;
}

inline std::error_code 
jwt_object::verify_with_leeway(uint32_t leeway) const noexcept
{

  //Check for the expiry timings
  if (has_claim(registered_claims::expiration)) {
    uint64_t curr_time = 
        std::chrono::duration_cast<
                 std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    auto itr = payload().create_json_obj().find("exp");
    if (! itr->is_number_unsigned()) return VerificationErrc::TypeConversionError;
    auto p_exp = itr->get<uint64_t>();

    if (curr_time > static_cast<uint64_t>(p_exp + leeway)) {
      return VerificationErrc::TokenExpired;
    }
  } 

  //Check for NBF
  if (has_claim(registered_claims::not_before))
  {
    uint64_t curr_time =
            std::chrono::duration_cast<
              std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    auto itr = payload().create_json_obj().find("nbf");
    if (! itr->is_number_unsigned()) return VerificationErrc::TypeConversionError;
    auto p_exp = itr->get<uint64_t>();

    if (static_cast<uint64_t>(p_exp - leeway) > curr_time) {
      return VerificationErrc::ImmatureSignature;
    }
  }

  return std::error_code{};
}


inline std::array<jwt::string_view, 3>
jwt_object::three_parts(const jwt::string_view enc_str)
{
  std::array<jwt::string_view, 3> result;

  size_t fpos = enc_str.find_first_of('.');
  assert (fpos != jwt::string_view::npos);

  result[0] = jwt::string_view{&enc_str[0], fpos};

  size_t spos = enc_str.find_first_of('.', fpos + 1);

  result[1] = jwt::string_view{&enc_str[fpos + 1], spos - fpos - 1};

  if (spos != enc_str.length()) {
    result[2] = jwt::string_view{&enc_str[spos + 1], enc_str.length() - spos - 1};
  }

  return result;
}

template <typename DecodeParams, typename Key, typename Hasher, typename... Rest>
void jwt_object::set_decode_params(DecodeParams& dparams, params::detail::secret_param<Key, Hasher>&&, Rest&&... args) {
  return set_decode_params(dparams, std::forward<Rest>(args)...);
}

template <typename DecodeParams, typename... Rest>
void jwt_object::set_decode_params(DecodeParams& dparams, params::detail::leeway_param l, Rest&&... args)
{
  dparams.leeway = l.get();
  jwt_object::set_decode_params(dparams, std::forward<Rest>(args)...);
}

template <typename DecodeParams, typename... Rest>
void jwt_object::set_decode_params(DecodeParams& dparams, params::detail::verify_param v, Rest&&... args)
{
  dparams.verify = v.get();
  jwt_object::set_decode_params(dparams, std::forward<Rest>(args)...);
}

template <typename DecodeParams, typename T, typename... Rest>
void jwt_object::set_decode_params(DecodeParams& dparams, const params::detail::checker_param<T>& c, Rest&&... args)
{
  jwt_object::set_decode_params(dparams, std::forward<Rest>(args)...);
}

template <typename DecodeParams>
void jwt_object::set_decode_params(DecodeParams&)
{
  return;
}

//==================================================================

template <typename SequenceT, typename... Args>
jwt_object decode(const jwt::string_view enc_str,
                  params::detail::algorithms_param<SequenceT>&& algos,
                  std::error_code& ec,
                  Args&&... args)
{
  if (algos.get().size() == 0) {
    ec = DecodeErrc::EmptyAlgoList;
    return jwt_object{};
  }

  auto check_algos = [&algos](const jwt_object& obj) -> std::error_code {
    //Verify if the algorithm set in the header
    //is any of the one expected by the client.
    auto alg = obj.header().algo();
    auto fitr = std::find_if(algos.get().begin(), 
                            algos.get().end(),
                            [alg](const auto& elem) 
                            {
                              return jwt::str_to_alg(elem) == alg;
                            });

    if (fitr == algos.get().end()) {
      return std::error_code{VerificationErrc::InvalidAlgorithm};
    }
    return std::error_code{};
  };

  return decode(enc_str, ec, params::custom_check(check_algos), std::forward<Args>(args)...); 
}

template <typename... Args>
jwt_object decode(const jwt::string_view enc_str,
                  std::error_code& ec,
                  Args&&... args)
{

  ec.clear();
  jwt_object obj;

  struct decode_params
  {

    /// Verify parameter. Defaulted to true.
    bool verify = true;

    /// Leeway parameter. Defaulted to zero seconds.
    uint32_t leeway = 0;
  };

  decode_params dparams{};
  

  //Signature must have atleast 2 dots
  auto dot_cnt = std::count_if(std::begin(enc_str), std::end(enc_str),
                               [](char ch) { return ch == '.'; });
  if (dot_cnt < 2) {
    ec = DecodeErrc::SignatureFormatError;
    return obj;
  }

  auto parts = jwt_object::three_parts(enc_str);

  //throws decode error
  jwt_header hdr{};
  hdr.decode(parts[0], ec);
  if (ec) {
    return obj;
  }
  //obj.header(jwt_header{parts[0]});
  obj.header(std::move(hdr));

  //If the algorithm is not NONE, it must not
  //have more than two dots ('.') and the split
  //must result in three strings with some length.
  if (obj.header().algo() != jwt::algorithm::NONE) {
    if (dot_cnt > 2) {
      ec = DecodeErrc::SignatureFormatError;
      return obj;
    }
    if (parts[2].length() == 0) {
      ec = DecodeErrc::SignatureFormatError;
      return obj;
    }
  }

  //throws decode error
  jwt_payload payload{};
  payload.decode(parts[1], ec);
  if (ec) {
    return obj;
  }
  obj.payload(std::move(payload));
  jwt_object::set_decode_params(dparams, std::forward<Args>(args)...);
  if (dparams.verify) {
    ec = obj.verify_with_leeway(dparams.leeway);

    if (ec) return obj;
    // Length of the encoded header and payload only.
    // Addition of '1' to account for the '.' character.
    auto l = parts[0].length() + 1 + parts[1].length();

    //MemoryAllocationError is not caught
    verify_result_t res = detail::verify(obj, enc_str.substr(0, l), parts[2], std::forward<Args>(args)...);
    if (res.second) {
      ec = res.second;
      return obj;
    }
    if (!res.first) {
      ec = VerificationErrc::InvalidSignature;
      return obj;
    }
  }

  return obj; 
}


template <typename SequenceT, typename... Args>
jwt_object decode(const jwt::string_view enc_str,
                  params::detail::algorithms_param<SequenceT>&& algos,
                  Args&&... args)
{
  std::error_code ec{};
  auto jwt_obj = decode(enc_str,
                        std::forward<params::detail::algorithms_param<SequenceT>>(algos),
                        ec,
                        std::forward<Args>(args)...);

  if (ec) {
    jwt_throw_exception(ec);
  }

  return jwt_obj;
}

template <typename... Args>
jwt_object decode(const jwt::string_view enc_str,
                  Args&&... args)
{
  std::error_code ec{};
  auto jwt_obj = decode(enc_str,
                        ec,
                        std::forward<Args>(args)...);

  if (ec) {
    jwt_throw_exception(ec);
  }

  return jwt_obj;
}

inline void 
jwt_throw_exception(const std::error_code& ec)
{
  const auto& cat = ec.category();

  if (&cat == &theVerificationErrorCategory ||
      std::string(cat.name()) == std::string(theVerificationErrorCategory.name()))
  {
    switch (static_cast<VerificationErrc>(ec.value()))
    {
      case VerificationErrc::InvalidAlgorithm:
      {
        throw InvalidAlgorithmError(ec.message());
      }
      case VerificationErrc::TokenExpired:
      {
        throw TokenExpiredError(ec.message());
      }
      case VerificationErrc::InvalidIssuer:
      {
        throw InvalidIssuerError(ec.message());
      }
      case VerificationErrc::InvalidAudience:
      {
        throw InvalidAudienceError(ec.message());
      }
      case VerificationErrc::InvalidSubject:
      {
        throw InvalidSubjectError(ec.message());
      }
      case VerificationErrc::InvalidIAT:
      {
        throw InvalidIATError(ec.message());
      }
      case VerificationErrc::InvalidJTI:
      {
        throw InvalidJTIError(ec.message());
      }
      case VerificationErrc::ImmatureSignature:
      {
        throw ImmatureSignatureError(ec.message());
      }
      case VerificationErrc::InvalidSignature:
      {
        throw InvalidSignatureError(ec.message());
      }
      case VerificationErrc::TypeConversionError:
      {
        throw TypeConversionError(ec.message());
      }
      default:
        assert (0 && "Unknown error code");
    };
  }

  if (&cat == &theDecodeErrorCategory ||
      std::string(cat.name()) == std::string(theDecodeErrorCategory.name()))
  {
    switch (static_cast<DecodeErrc>(ec.value()))
    {
      case DecodeErrc::SignatureFormatError:
      {
        throw SignatureFormatError(ec.message());
      }
      case DecodeErrc::KeyNotPresent:
      {
        throw KeyNotPresentError(ec.message());
      }
      case DecodeErrc::KeyNotRequiredForNoneAlg:
      {
        // Not an error. Just to be ignored.
        break;
      }
      default:
      {
        throw DecodeError(ec.message());
      }
    };

    assert (0 && "Unknown error code");
  }

  if (&cat == &theAlgorithmErrCategory ||
      std::string(cat.name()) == std::string(theAlgorithmErrCategory.name()))
  {
    switch (static_cast<AlgorithmErrc>(ec.value()))
    {
      case AlgorithmErrc::VerificationErr:
      {
        throw InvalidSignatureError(ec.message());
      }
      case AlgorithmErrc::NoneAlgorithmUsed:
      {
        //Not an error actually.
        break;
      }
      default:
        assert (0 && "Unknown error code or not to be treated as an error");
    };
  }
  return;
}

} // END namespace jwt


#endif
