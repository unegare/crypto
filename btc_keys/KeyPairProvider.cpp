#include <iostream>
#include <ostream>
#include <string_view>
#include <cstdlib>
#include <cstring>

#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>
#include <openssl/ripemd.h>

#include "libbase58/libbase58.h"

#include "KeyPairProvider.h"

KeyPairProvider::KeyPairProvider() {
  ctx = BN_CTX_new();
  eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
}

KeyPairProvider::~KeyPairProvider() {
  BN_CTX_free(ctx);
  EC_KEY_free(eckey);
}

std::optional<KeyPairProvider::KeyPair> KeyPairProvider::getRandomPair(bool compressed) const {
  const EC_GROUP *group = EC_KEY_get0_group(eckey); 
  EC_POINT *pub_key = EC_POINT_new(group);
  BIGNUM *priv_key = BN_new();

  BN_priv_rand(priv_key, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

  if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {
    return std::nullopt; 
  }

  EC_KEY_set_public_key(eckey, pub_key);

  BIGNUM *pub_bn = EC_POINT_point2bn(group, pub_key, compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED, NULL, ctx);

  EC_POINT_free (pub_key);

  return pub_bn ? std::make_optional(KeyPair(priv_key, pub_bn, compressed)) : std::nullopt;
}

std::optional<KeyPairProvider::KeyPair> KeyPairProvider::getPairWithPriv(std::string_view priv_hex, bool compressed) const {
  const EC_GROUP *group = EC_KEY_get0_group(eckey); 
  EC_POINT *pub_key = EC_POINT_new(group);
  BIGNUM *priv_key = BN_new();

  BN_hex2bn(&priv_key, priv_hex.data());

  if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {
    return std::nullopt; 
  }

  EC_KEY_set_public_key(eckey, pub_key);

  BIGNUM *pub_bn = EC_POINT_point2bn(group, pub_key, compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED, NULL, ctx);

  EC_POINT_free (pub_key);

  return pub_bn ? std::make_optional(KeyPair(priv_key, pub_bn, compressed)) : std::nullopt;
}

KeyPairProvider::KeyPair::KeyPair(BIGNUM *_priv, BIGNUM *_pub, bool _compressed): priv(_priv), pub(_pub), compressed(_compressed), priv_hex(NULL), pub_hex(NULL), wif(NULL), p2pkh_b58check(NULL) {
}

KeyPairProvider::KeyPair::KeyPair(KeyPair &&kp): priv(kp.priv), pub(kp.pub), compressed(kp.compressed), priv_hex(kp.priv_hex), pub_hex(kp.pub_hex), wif(kp.wif), p2pkh_b58check(kp.p2pkh_b58check) {
  kp.priv = NULL;
  kp.pub = NULL;
  kp.priv_hex = NULL;
  kp.pub_hex = NULL;
  kp.wif = NULL;
  kp.p2pkh_b58check = NULL;
}

KeyPairProvider::KeyPair::~KeyPair() {
  BN_free(priv);
  BN_free(pub);
  free(priv_hex);
  free(pub_hex);
  free(wif);
  free(p2pkh_b58check);
}

std::optional<std::string_view> KeyPairProvider::KeyPair::getPrivHex() const {
  if (priv_hex) return priv_hex;
  priv_hex = BN_bn2hex(priv);
  if (!priv_hex) {
    return std::nullopt;
  }
  return priv_hex;
}

std::optional<std::string_view> KeyPairProvider::KeyPair::getPubHex() const {
  if (pub_hex) return pub_hex;
  pub_hex = BN_bn2hex(pub);
  if (!pub_hex) {
    return std::nullopt;
  }
  return pub_hex;
}

std::optional<std::string_view> KeyPairProvider::KeyPair::getWIF() const {
  if (wif) return wif;
  size_t len = BN_num_bytes(priv);
  unsigned char *bin = (unsigned char *)malloc(len + 1 + (compressed ? 1 : 0) + 4);
  if (!bin) {
    return std::nullopt;
  }
  if (!BN_bn2bin(priv, bin + 1)) {
    free(bin);
    return std::nullopt;
  }

  bin[0] = 0x80;
  bin[len + 1] = compressed ? 1 : 0;

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  if (!SHA256_Init(&sha256) || !SHA256_Update(&sha256, bin, compressed ? len + 2 : len + 1) || !SHA256_Final(hash, &sha256)) {
    free(bin);
    return std::nullopt;
  }
  if (!SHA256_Init(&sha256) || !SHA256_Update(&sha256, hash, SHA256_DIGEST_LENGTH) || !SHA256_Final(hash, &sha256)) {
    free(bin);
    return std::nullopt;
  }

  memcpy(bin + len + 1 + (compressed ? 1 : 0), hash, 4);
  
  size_t b58sz = 53;
  wif = (char*)malloc(b58sz);
  if (!wif) {
    free(bin);
    return std::nullopt;
  }
  if (!b58enc(wif, &b58sz, bin, len + 1 + (compressed ? 1 : 0) + 4)) {
    free(bin);
    free(wif);
    wif = NULL;
    return std::nullopt;
  }

  free(bin);

  return wif;
}

std::optional<std::string_view> KeyPairProvider::KeyPair::getP2PKH() const {
  if (p2pkh_b58check) return p2pkh_b58check;
  unsigned char hash[std::max(RIPEMD160_DIGEST_LENGTH, SHA256_DIGEST_LENGTH) + 1 + 4]; // actually allocation of SHA256_DIGEST_LENGTH would be enough since it is 32 and RIPEMD160_DIGEST_LENGTH is 20

  size_t len = BN_num_bytes(pub);
  unsigned char *bin = (unsigned char *)malloc(len);
  if (!bin) {
    return std::nullopt;
  }
  if (!BN_bn2bin(pub, bin)) {
    free(bin);
    return std::nullopt;
  }

  SHA256_CTX sha256;
  if (!SHA256_Init(&sha256) || !SHA256_Update(&sha256, bin, len) || !SHA256_Final(hash +1, &sha256)) {
    free(bin);
    return std::nullopt;
  }

  free(bin);

  if (RIPEMD160_CTX ripemd160; !RIPEMD160_Init(&ripemd160) || !RIPEMD160_Update(&ripemd160, hash +1, SHA256_DIGEST_LENGTH) || !RIPEMD160_Final(hash +1, &ripemd160)) {
    return std::nullopt;
  }

  hash[0] = 0x00; //Network

  unsigned char hash_tmp[SHA256_DIGEST_LENGTH];

  if (!SHA256_Init(&sha256) || !SHA256_Update(&sha256, hash, RIPEMD160_DIGEST_LENGTH +1) || !SHA256_Final(hash_tmp, &sha256)) {
    return std::nullopt;
  }
  if (!SHA256_Init(&sha256) || !SHA256_Update(&sha256, hash_tmp, SHA256_DIGEST_LENGTH) || !SHA256_Final(hash_tmp, &sha256)) {
    return std::nullopt;
  }

  memcpy(hash + RIPEMD160_DIGEST_LENGTH + 1, hash_tmp, 4);
  
  size_t p2pkh_len = 50; // 36 should be enough
  p2pkh_b58check = (char*)malloc(p2pkh_len);
  if (!p2pkh_b58check) {
    return std::nullopt;
  }

  if (!b58enc(p2pkh_b58check, &p2pkh_len, hash, RIPEMD160_DIGEST_LENGTH + 1 + 4)) {
    free(p2pkh_b58check);
    p2pkh_b58check = NULL;
    return std::nullopt;
  }

  return p2pkh_b58check;
}

std::ostream& operator<< (std::ostream &os, const KeyPairProvider::KeyPair &k) {
  os << "priv_hex: " << k.getPrivHex().value_or("Err") << "\n"
     << "pub_hex: " << k.getPubHex().value_or("Err") << "\n"
     << "WIF: " << k.getWIF().value_or("Err") << "\n"
     << "P2PKH: " << k.getP2PKH().value_or("Err") << "\n";
  return os;
}
