;; Vulnerable Lending Pool - Test contract for Clarity Shield
;; Contains intentional vulnerabilities for scanner testing

(define-data-var pool-balance uint u0)
(define-data-var admin principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
(define-map deposits { user: principal } { amount: uint, unlock-height: uint })
(define-map loans { borrower: principal } { amount: uint, collateral: uint })

;; VULN: contract-caller for admin check
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq contract-caller (var-get admin)) (err u401))
    (var-set admin new-admin)
    (ok true)))

;; VULN: No auth check on deposit withdrawal  
(define-public (withdraw (amount uint))
  (let ((deposit-info (unwrap-panic (map-get? deposits { user: tx-sender }))))
    ;; VULN: block-height for unlock deadline
    (asserts! (>= block-height (get unlock-height deposit-info)) (err u100))
    ;; VULN: as-contract stx-transfer without amount limit
    (stx-transfer? amount (as-contract tx-sender) tx-sender)))

;; VULN: Public function with no auth that changes state
(define-public (liquidate (borrower principal))
  (let ((loan-info (unwrap-panic (map-get? loans { borrower: borrower }))))
    (map-delete loans { borrower: borrower })
    (stx-transfer? (get collateral loan-info) (as-contract tx-sender) tx-sender)))

;; VULN: Dynamic dispatch via trait
(define-public (swap-collateral (<oracle-trait> oracle))
  (let ((price (unwrap-panic (contract-call? oracle get-price))))
    (ok price)))

;; VULN: read-only with state change attempt
(define-read-only (debug-reset)
  (begin
    (map-delete deposits { user: tx-sender })
    (ok true)))

;; VULN: map-set without validation
(define-public (force-deposit (user principal) (amount uint))
  (begin
    (map-set deposits { user: user } { amount: amount, unlock-height: (+ block-height u100) })
    (ok true)))

;; VULN: unhandled contract-call? response
(define-public (claim-rewards (pool-contract principal))
  (begin
    (contract-call? .reward-pool claim tx-sender)
    (ok true)))
