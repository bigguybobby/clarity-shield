;; SIP-013 Semi-Fungible Token — incomplete implementation for testing
;; Missing: transfer-memo, get-overall-balance, get-overall-supply, get-decimals

(define-fungible-token game-credits)

(define-map token-balances {token-id: uint, owner: principal} {amount: uint})
(define-map token-supplies {token-id: uint} {supply: uint})
(define-data-var last-token-id uint u0)

;; Has transfer
(define-public (transfer (token-id uint) (amount uint) (sender principal) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender sender) (err u401))
    (ft-mint? game-credits amount recipient)
  )
)

;; Has get-balance
(define-read-only (get-balance (token-id uint) (who principal))
  (ok (default-to u0 (get amount (map-get? token-balances {token-id: token-id, owner: who}))))
)

;; Has get-total-supply
(define-read-only (get-total-supply (token-id uint))
  (ok (default-to u0 (get supply (map-get? token-supplies {token-id: token-id}))))
)

;; Has get-token-uri
(define-read-only (get-token-uri (token-id uint))
  (ok (some "https://example.com/metadata/{id}"))
)

;; Missing: transfer-memo, get-overall-balance, get-overall-supply, get-decimals
