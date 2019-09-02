(ns ku.main
  (:require [ku.core :as ku])
  (:gen-class))

(defn -main [& args]
  (println (ku/decrypt-vault (slurp (first args))
                             (System/getenv "VAULT_PASSWORD"))))
