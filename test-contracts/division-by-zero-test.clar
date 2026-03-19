;; Test contract for #94 Division by Zero DoS detector

;; ==============================
;; VULNERABLE: division by user-controlled or unvalidated denominator
;; ==============================

;; Data vars
(define-data-var pool-total-shares uint u0)
(define-data-var total-staked uint u0)
(define-data-var fee-rate uint u0)

;; Vulnerable #1: divides by a function parameter without zero-check
(define-public (calculate-share (amount uint) (total-supply uint))
  (ok (/ amount total-supply))
)

;; Vulnerable #2: divides by a data-var that could be zero (e.g. empty pool)
(define-public (get-price-per-share (deposit uint))
  (ok (/ deposit (var-get pool-total-shares)))
)

;; Vulnerable #3: divides by arithmetic result that could be zero
(define-public (calculate-reward (reward uint) (user-stake uint))
  (ok (/ (* reward user-stake) (var-get total-staked)))
)

;; ==============================
;; SAFE: division with proper zero-checks
;; ==============================

;; Safe #1: asserts denominator is not zero before dividing
(define-public (safe-calculate-share (amount uint) (total-supply uint))
  (begin
    (asserts! (> total-supply u0) (err u100))
    (ok (/ amount total-supply))
  )
)

;; Safe #2: uses if-check before division
(define-public (safe-price-per-share (deposit uint))
  (let ((shares (var-get pool-total-shares)))
    (if (is-eq shares u0)
      (ok deposit)
      (ok (/ deposit shares))
    )
  )
)

;; Safe #3: divides by a constant (never zero)
(define-public (calculate-percentage (amount uint))
  (ok (/ amount u100))
)

;; Safe #4: read-only function (lower risk, not flagged)
(define-read-only (read-share-price (amount uint) (supply uint))
  (/ amount supply)
)

;; Safe #5: private function (not externally callable)
(define-private (internal-division (a uint) (b uint))
  (/ a b)
)

;; Safe #6: division by well-known non-zero variable with asserts before
(define-public (calculate-fee (amount uint))
  (begin
    (asserts! (> (var-get fee-rate) u0) (err u200))
    (ok (/ amount (var-get fee-rate)))
  )
)

;; ==============================
;; NON-RELEVANT: no division
;; ==============================

(define-public (simple-add (a uint) (b uint))
  (ok (+ a b))
)
