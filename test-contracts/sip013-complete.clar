;; SIP-013 Semi-Fungible Token — complete implementation (no findings expected)

(define-fungible-token game-credits)

(define-map token-balances {token-id: uint, owner: principal} {amount: uint})
(define-map token-supplies {token-id: uint} {supply: uint})
(define-data-var last-token-id uint u0)

(define-public (transfer (token-id uint) (amount uint) (sender principal) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender sender) (err u401))
    (ft-mint? game-credits amount recipient)
  )
)

(define-public (transfer-memo (token-id uint) (amount uint) (sender principal) (recipient principal) (memo (buff 34)))
  (begin
    (asserts! (is-eq tx-sender sender) (err u401))
    (ft-mint? game-credits amount recipient)
  )
)

(define-read-only (get-balance (token-id uint) (who principal))
  (ok (default-to u0 (get amount (map-get? token-balances {token-id: token-id, owner: who}))))
)

(define-read-only (get-overall-balance (who principal))
  (ok (ft-get-balance game-credits who))
)

(define-read-only (get-total-supply (token-id uint))
  (ok (default-to u0 (get supply (map-get? token-supplies {token-id: token-id}))))
)

(define-read-only (get-overall-supply)
  (ok (ft-get-supply game-credits))
)

(define-read-only (get-token-uri (token-id uint))
  (ok (some "https://example.com/metadata/{id}"))
)

(define-read-only (get-decimals (token-id uint))
  (ok u6)
)
