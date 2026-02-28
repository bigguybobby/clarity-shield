;; Vulnerable DeFi V2 - Tests new detectors (#36-40)

;; Secret key accidentally left in contract
(define-constant SECRET-HASH 0x4a2f8c9e1b3d5a7f0e2c4b6d8a1f3e5c7b9d0a2e4f6c8b1d3a5e7f9c0b2d4a6b)

;; Token definition
(define-fungible-token defi-token)
(define-data-var total-supply uint u0)

;; Unprotected init - no guard against re-initialization
(define-public (initialize (new-owner principal))
  (begin
    (var-set total-supply u1000000)
    (ft-mint? defi-token u1000000 new-owner)
  )
)

;; Swap without slippage protection
(define-public (swap-tokens (amount uint))
  (let ((price (var-get total-supply)))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; DoS via external calls in fold
(define-public (distribute-rewards (recipients (list 100 principal)))
  (begin
    (fold distribute-to-one recipients u0)
    (ok true)
  )
)

(define-private (distribute-to-one (recipient principal) (idx uint))
  (begin
    (unwrap-panic (stx-transfer? u100 (as-contract tx-sender) recipient))
    (+ idx u1)
  )
)

;; Unsafe fold accumulator
(define-read-only (sum-balances (accounts (list 200 principal)))
  (fold add-balance accounts u0)
)

(define-private (add-balance (account principal) (acc uint))
  (+ acc (ft-get-balance defi-token account))
)
