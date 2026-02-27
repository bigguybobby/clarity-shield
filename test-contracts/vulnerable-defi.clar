;; Vulnerable DeFi Contract — exercises new v1.3.0 detectors
;; Unsafe casting, unprotected URI, SIP-010 gaps, unguarded as-contract

(define-fungible-token vuln-token)
(define-data-var token-uri (string-utf8 256) u"https://example.com/token.json")
(define-data-var fee-rate uint u500)
(define-data-var admin principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)

;; Unprotected token URI setter — no auth check
(define-public (set-token-uri (new-uri (string-utf8 256)))
  (begin
    (var-set token-uri new-uri)
    (ok true)))

;; Unsafe casting without range check
(define-public (convert-and-send (amount uint) (recipient principal))
  (let ((signed-amount (to-int amount)))
    (stx-transfer? amount tx-sender recipient)))

;; Unguarded as-contract — anyone can trigger contract-level ops
(define-public (withdraw-pool (amount uint) (recipient principal))
  (as-contract (stx-transfer? amount tx-sender recipient)))

;; Transfer using var-get amount without bounds
(define-public (pay-fee (recipient principal))
  (stx-transfer? (var-get fee-rate) tx-sender recipient))

;; Missing SIP-010 functions: only has transfer, missing get-name, get-symbol, etc.
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (begin
    (asserts! (is-eq tx-sender sender) (err u401))
    (ft-transfer? vuln-token amount sender recipient)))
