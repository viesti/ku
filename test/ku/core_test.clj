(ns ku.core-test
  (:require [clojure.test :refer [deftest is]]
            [ku.core :as sut]
            [clojure.java.io :as io]))

(deftest read-vault
  (is (= "moi"
         (.trim (sut/decrypt-vault-file (io/resource "test-vault") "foo")))))
