#ifndef KEYPAIRPROVIDER_H_
#define KEYPAIRPROVIDER_H_

#include <optional>

#include <openssl/ec.h>
#include <openssl/bn.h>

class KeyPairProvider {
  mutable BN_CTX *ctx;
  mutable EC_KEY *eckey;
public:
  KeyPairProvider();
  ~KeyPairProvider();

  typedef class KeyPair {
    BIGNUM *priv;
    BIGNUM *pub;
    bool compressed;
    mutable char *priv_hex;
    mutable char *pub_hex;
    mutable char *wif;
    mutable char *p2pkh_b58check;
    KeyPair() = delete;
    public:
      KeyPair(BIGNUM *_priv, BIGNUM *_pub, bool _compressed);
      KeyPair(KeyPair &&kp);
      ~KeyPair();

      std::optional<std::string_view> getPrivHex() const;
      std::optional<std::string_view> getPubHex() const;
      std::optional<std::string_view> getWIF() const;
      std::optional<std::string_view> getP2PKH() const;
  } KeyPair;

  std::optional<KeyPair> getRandomPair(bool compressed) const;
  std::optional<KeyPair> getPairWithPriv(std::string_view priv_hex, bool compressed) const;
};

std::ostream& operator<< (std::ostream &os, const KeyPairProvider::KeyPair &k);

#endif
