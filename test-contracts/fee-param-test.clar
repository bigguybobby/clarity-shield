;; Test contract for detector #78: Unvalidated Fee/Percentage Parameters
;; Tests functions that accept fee/rate/commission params without bounds checks

;; --- Data vars ---
(define-fungible-token my-token u1000000)
(define-data-var contract-owner principal tx-sender)

;; VULNERABLE: swap function with unbounded fee-percent parameter
(define-public (swap-with-fee (amount uint) (fee-percent uint))
  (let (
    (fee (/ (* amount fee-percent) u100))
    (net-amount (- amount fee))
  )
    (stx-transfer? net-amount tx-sender (var-get contract-owner))
  )
)

;; VULNERABLE: set-commission with no cap (could be set to 100%)
(define-public (set-commission-rate (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
    (var-set commission-rate new-rate)
    (ok true)
  )
)
(define-data-var commission-rate uint u5)

;; SAFE: fee parameter with explicit bounds check
(define-public (swap-with-bounded-fee (amount uint) (fee-bps uint))
  (begin
    (asserts! (<= fee-bps u1000) (err u400))
    (let (
      (fee (/ (* amount fee-bps) u10000))
      (net-amount (- amount fee))
    )
      (stx-transfer? net-amount tx-sender (var-get contract-owner))
    )
  )
)

;; SAFE: percentage parameter with upper bound assertion
(define-public (set-reward-percentage (percentage uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
    (asserts! (< percentage u50) (err u401))
    (ok true)
  )
)

;; SAFE: no fee/rate parameter — just a normal function
(define-public (transfer-fixed (amount uint) (recipient principal))
  (stx-transfer? amount tx-sender recipient)
)
