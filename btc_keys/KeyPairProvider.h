#ifndef KEYPAIRPROVIDER_H_
#define KEYPAIRPROVIDER_H_

#include <optional>
#include <string>
#include <string_view>
#include <memory>

#include <openssl/ec.h>
#include <openssl/bn.h>

class KeyPairProvider {
//  mutable BN_CTX *ctx;
//  mutable EC_KEY *eckey;

// s_ptr.get() always returns NON-const ptr
  std::shared_ptr<BN_CTX> ctx; // since all stuff is done via s_ptr.get() there is no need to make it mutable
  std::shared_ptr<EC_KEY> eckey; // since all stuff is done via s_ptr.get() there is no need to make it mutable
public:
  KeyPairProvider();
  ~KeyPairProvider();

  typedef class KeyPair {
//    std::weak_ptr<BN_CTX> w_ctx;
//    std::weak_ptr<EC_KEY> w_eckey;
    std::shared_ptr<BN_CTX> s_ctx; // since all stuff is done via s_ptr.get() there is no need to make it mutable
    std::shared_ptr<EC_KEY> s_eckey; // since all stuff is done via s_ptr.get() there is no need to make it mutable
    BIGNUM *priv;
    BIGNUM *pub;
    bool compressed;
    mutable char *priv_hex;
    mutable char *pub_hex;
    mutable char *wif;
    mutable char *p2pkh_b58check;
    mutable char *eth_addr;
    KeyPair() = delete;

    bool derivePublic();
    void reset();
    public:
      KeyPair(BIGNUM *_priv, BIGNUM *_pub, bool _compressed);
//      KeyPair(std::weak_ptr<BN_CTX> _ctx, std::weak_ptr<EC_KEY> _eckey, BIGNUM *_priv, BIGNUM *_pub, bool _compressed);
      KeyPair(std::shared_ptr<BN_CTX> _ctx, std::shared_ptr<EC_KEY> _eckey, BIGNUM *_priv, BIGNUM *_pub, bool _compressed);
      KeyPair(KeyPair &&kp);
      ~KeyPair();

      std::optional<std::string_view> getPrivHex() const;
      std::optional<std::string_view> getPubHex() const;
      std::optional<std::string_view> getWIF() const;
      std::optional<std::string_view> getP2PKH() const;
      std::optional<std::string_view> getEthAddr() const;

      bool inc();
      bool add(BIGNUM *bn);

      KeyPair& operator=(KeyPair&&);
  } KeyPair;

  std::optional<KeyPair> getRandomPair(bool compressed = 1) const;
  std::optional<KeyPair> getPairWithPriv(std::string priv_hex, bool compressed = 1) const;
};

std::ostream& operator<< (std::ostream &os, const KeyPairProvider::KeyPair &k);

#endif
