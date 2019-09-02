(ns ku.core
  (:require [clojure.string :as str])
  (:import (javax.crypto SecretKeyFactory Cipher Mac)
           (javax.crypto.spec SecretKeySpec PBEKeySpec IvParameterSpec)
           (java.util Arrays)))

(def ansible-vault-format-id "$ANSIBLE_VAULT")
(def versions #{"1.1" "1.2"})
(def ciphers #{"AES256"})

(defn parse-header [header]
  (zipmap [:format-id :version :cipher :vault-id]
          (str/split header #";")))

(defn hex-str->bytes ^bytes [^String string]
  (let [characters (.toCharArray string)
        byte-count (/ (alength characters)
                      2)
        _  (when-not (zero? (mod byte-count 2))
             (throw (IllegalAccessException. "Hex string has odd number of characters")))
        bytes (byte-array byte-count)]
    (loop [byte-idx 0
           char-idx 0]
      (if (< char-idx (alength characters))
        (do
          (aset-byte bytes byte-idx (unchecked-byte (bit-and (bit-or (bit-shift-left (Character/digit (aget characters char-idx) 16) 4)
                                                                     (Character/digit (aget characters (inc char-idx)) 16))
                                                             0xFF)))
          (recur (inc byte-idx)
                 (+ char-idx 2)))
        bytes))))

(defn decrypt-vault [^String vault-text ^String password]
  (let [[header & payload] (str/split-lines vault-text)
        {:keys [format-id version cipher]} (parse-header header)
        _ (when-not (and (versions version)
                         (= ansible-vault-format-id format-id)
                         (ciphers cipher))
            (throw (IllegalArgumentException. "Uknown Vault format")))
        [salt-text hmac-text cipher-text] (-> (hex-str->bytes (str/join "" payload))
                                              (String. "UTF-8")
                                              (str/split-lines))
        salt-bytes (hex-str->bytes salt-text)
        hmac-bytes (hex-str->bytes hmac-text)
        ciphertext-bytes (hex-str->bytes cipher-text)
        key-spec (PBEKeySpec. (.toCharArray password) salt-bytes 10000 (* 8 (+ (* 2 32) 16)))
        key-bytes (-> (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
                      (.generateSecret key-spec)
                      (.getEncoded ))
        crypto-key-spec (SecretKeySpec. (Arrays/copyOfRange key-bytes 0 32) "AES")
        cipher (Cipher/getInstance "AES/CTR/PKCS5PADDING")
        iv-spec (IvParameterSpec. (Arrays/copyOfRange key-bytes 64 80))
        mac (Mac/getInstance "HmacSHA256")
        hmac-key-spec (SecretKeySpec. (Arrays/copyOfRange key-bytes 32 64) "HmacSHa256")]
    (.init mac hmac-key-spec)
    (when-not (Arrays/equals hmac-bytes (.doFinal mac ciphertext-bytes))
      (throw (IllegalArgumentException. "HMAC verification failed")))
    (.init cipher Cipher/DECRYPT_MODE crypto-key-spec iv-spec)
    (String. (.doFinal cipher ciphertext-bytes) "UTF-8")))

(defn decrypt-vault-file [file password]
  (decrypt-vault (slurp file) password))
