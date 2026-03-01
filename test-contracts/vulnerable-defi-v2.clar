;; vulnerable-defi-v2.clar — Test contract for v1.9.0 detectors

;; #46 - Uncapped fee
(define-data-var fee-rate uint u100)
(define-public (set-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
    (var-set fee-rate new-fee)
    (ok true)))

;; #47 - Swap without deadline
(define-public (swap (amount uint) (min-out uint))
  (let ((fee (/ (* amount (var-get fee-rate)) u10000)))
    (try! (stx-transfer? (- amount fee) tx-sender (var-get treasury)))
    (ok (- amount fee))
  )
)

;; #48 - Division before multiplication
(define-read-only (calc-share (amount uint) (total uint) (reward uint))
  (* (/ amount total) reward)
)

;; #49 - Unchecked map-insert
(define-map user-stakes { user: principal } { amount: uint })
(define-public (stake (amount uint))
  (begin
    (map-insert user-stakes { user: tx-sender } { amount: amount })
    (ok true)))

;; #50 - STX transfer to variable recipient
(define-data-var treasury principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
(define-data-var contract-owner principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)

(define-public (set-treasury (new-treasury principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
    (var-set treasury new-treasury)
    (ok true)))

(define-public (withdraw (amount uint))
  (stx-transfer? amount (as-contract tx-sender) (var-get treasury)))
