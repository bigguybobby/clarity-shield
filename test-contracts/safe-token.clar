;; Safe Token Contract
;; Example of properly secured Clarity contract

(define-fungible-token safe-token)

(define-data-var contract-owner principal tx-sender)
(define-data-var paused bool false)

(define-constant ERR_UNAUTHORIZED (err u403))
(define-constant ERR_PAUSED (err u405))
(define-constant ERR_INVALID_AMOUNT (err u400))

;; SAFE: Uses tx-sender for authorization
(define-private (is-owner)
  (is-eq tx-sender (var-get contract-owner)))

;; SAFE: Proper authorization check
(define-public (mint (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (asserts! (not (var-get paused)) ERR_PAUSED)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    (ft-mint? safe-token amount recipient)))

;; SAFE: tx-sender used correctly
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (ok (var-set contract-owner new-owner))))

;; SAFE: Proper response handling with try!
(define-public (transfer (amount uint) (recipient principal))
  (begin
    (asserts! (not (var-get paused)) ERR_PAUSED)
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    ;; SAFE: try! propagates errors properly
    ;; @post-condition sender loses exactly `amount` tokens
    (try! (ft-transfer? safe-token amount tx-sender recipient))
    (ok true)))

;; SAFE: Burn with proper error handling using match
(define-public (burn (amount uint))
  (begin
    (asserts! (> amount u0) ERR_INVALID_AMOUNT)
    ;; SAFE: match handles both success and error cases
    (match (ft-burn? safe-token amount tx-sender)
      success (ok true)
      error (err error))))

;; SAFE: default-to handles missing map values
(define-read-only (get-balance (account principal))
  (ok (ft-get-balance safe-token account)))

(define-read-only (get-owner)
  (ok (var-get contract-owner)))

(define-read-only (is-paused)
  (ok (var-get paused)))
