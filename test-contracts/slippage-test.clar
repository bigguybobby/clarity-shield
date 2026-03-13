;; Test contract for detector #79: Missing Slippage Protection
;; Contains vulnerable and safe swap functions

;; --- Data vars ---
(define-data-var pool-balance-x uint u1000000)
(define-data-var pool-balance-y uint u1000000)

;; VULNERABLE: swap function without any slippage protection
(define-public (swap-x-for-y (amount-in uint))
  (let (
    (balance-x (var-get pool-balance-x))
    (balance-y (var-get pool-balance-y))
    (amount-out (/ (* amount-in balance-y) (+ balance-x amount-in)))
  )
    (try! (stx-transfer? amount-in tx-sender (as-contract tx-sender)))
    (var-set pool-balance-x (+ balance-x amount-in))
    (var-set pool-balance-y (- balance-y amount-out))
    (ok amount-out)
  )
)

;; VULNERABLE: exchange function without min-output check
(define-public (exchange-tokens (dx uint))
  (let (
    (dy (/ (* dx u997 (var-get pool-balance-y)) (+ (* (var-get pool-balance-x) u1000) (* dx u997))))
  )
    (try! (ft-transfer? token-x dx tx-sender (as-contract tx-sender)))
    (ok dy)
  )
)

;; SAFE: swap with min-amount-out parameter
(define-public (swap-with-min-out (amount-in uint) (min-amount-out uint))
  (let (
    (balance-x (var-get pool-balance-x))
    (balance-y (var-get pool-balance-y))
    (amount-out (/ (* amount-in balance-y) (+ balance-x amount-in)))
  )
    (asserts! (>= amount-out min-amount-out) (err u1001))
    (try! (stx-transfer? amount-in tx-sender (as-contract tx-sender)))
    (ok amount-out)
  )
)

;; SAFE: trade with slippage tolerance
(define-public (trade-with-slippage (amount uint) (slippage-bps uint))
  (let (
    (output (/ (* amount (var-get pool-balance-y)) (var-get pool-balance-x)))
    (min-out (/ (* output (- u10000 slippage-bps)) u10000))
  )
    (asserts! (>= output min-out) (err u1002))
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok output)
  )
)

;; SAFE: non-swap function with transfer (should NOT trigger)
(define-public (deposit (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)
  )
)
