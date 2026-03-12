;; Test contract for zero-amount validation detector (#75)

;; ---- VULNERABLE: transfer without zero-amount check ----
(define-public (transfer-tokens (amount uint) (recipient principal))
  (stx-transfer? amount tx-sender recipient)
)

;; ---- VULNERABLE: mint without zero-amount check ----
(define-public (mint-tokens (amount uint) (recipient principal))
  (ft-mint? my-token amount recipient)
)

;; ---- SAFE: has zero-amount assertion ----
(define-public (safe-transfer (amount uint) (recipient principal))
  (begin
    (asserts! (> amount u0) (err u100))
    (stx-transfer? amount tx-sender recipient)
  )
)

;; ---- SAFE: checks amount >= u1 ----
(define-public (safe-mint (amount uint) (recipient principal))
  (begin
    (asserts! (>= amount u1) (err u101))
    (ft-mint? my-token amount recipient)
  )
)

;; ---- SAFE: no amount parameter (uses constant) ----
(define-public (fixed-transfer (recipient principal))
  (stx-transfer? u1000 tx-sender recipient)
)
