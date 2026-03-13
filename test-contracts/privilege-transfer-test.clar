;; Test contract for single-step privilege transfer detector (#77)

;; --- Data vars for ownership ---
(define-data-var contract-owner principal tx-sender)
(define-data-var admin-address principal tx-sender)
(define-data-var pending-owner (optional principal) none)

;; VULNERABLE: Single-step owner transfer — typo = permanent lockout
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set contract-owner new-owner)
    (ok true)
  )
)

;; VULNERABLE: Single-step admin transfer via different var name
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-address)) (err u401))
    (var-set admin-address new-admin)
    (ok true)
  )
)

;; SAFE: Two-step transfer with propose + accept
(define-public (propose-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set pending-owner (some new-owner))
    (ok true)
  )
)

(define-public (accept-ownership)
  (let ((pending (unwrap! (var-get pending-owner) (err u404))))
    (asserts! (is-eq tx-sender pending) (err u403))
    (var-set contract-owner pending)
    (var-set pending-owner none)
    (ok true)
  )
)

;; SAFE: Owner setting themselves (not a transfer to arbitrary principal)
(define-public (reclaim-ownership)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set contract-owner tx-sender)
    (ok true)
  )
)
