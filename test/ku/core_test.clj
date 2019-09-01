(ns ku.core-test
  (:require [clojure.test :refer [deftest is]]
            [ku.core :as sut]
            [clojure.java.io :as io]))

(deftest read-vault
  (is (= "moi"
         (.trim (sut/read-vault (io/resource "test-vault") "foo")))))
