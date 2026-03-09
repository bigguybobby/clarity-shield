;; detector-regression.clar — Regression test contract for detectors #3, #4, #13, #38

;; === REENTRANCY PATTERN (#13) ===
;; State change AFTER contract-call? — should trigger
(define-map balances {user: principal} {amount: uint})
(define-public (withdraw-unsafe (amount uint))
  (begin
    (try! (contract-call? .token-contract transfer amount tx-sender (as-contract tx-sender)))
    (map-set balances {user: tx-sender} {amount: u0})
    (ok true)))

;; Safe version: state change BEFORE external call — should NOT trigger
(define-public (withdraw-safe (amount uint))
  (begin
    (map-set balances {user: tx-sender} {amount: u0})
    (try! (contract-call? .token-contract transfer amount tx-sender (as-contract tx-sender)))
    (ok true)))

;; === ARITHMETIC SAFETY (#3) ===
;; Unchecked uint arithmetic — should trigger
(define-public (add-amounts (a uint) (b uint))
  (ok (+ a uint b uint)))

;; Checked arithmetic — should NOT trigger
(define-public (add-amounts-safe (a uint) (b uint))
  (begin
    (asserts! (<= (+ a b) u1000000) (err u500))
    (ok (+ a b))))

;; === PUBLIC FUNCTION AUTH (#4) ===
;; Sensitive admin function with no auth — should trigger
(define-data-var fee-rate uint u100)
(define-public (set-fee-rate (new-rate uint))
  (begin
    (var-set fee-rate new-rate)
    (ok true)))

;; Admin function WITH auth — should NOT trigger
(define-data-var admin principal tx-sender)
(define-public (admin-set-fee (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (var-set fee-rate new-rate)
    (ok true)))

;; === DENIAL OF SERVICE (#38) ===
;; External call inside fold — should trigger
(define-public (distribute-rewards (recipients (list 200 principal)))
  (begin
    (fold distribute-one recipients u0)
    (ok true)))

(define-private (distribute-one (recipient principal) (idx uint))
  (begin
    (unwrap-panic (stx-transfer? u100 tx-sender recipient))
    (+ idx u1)))
