;; Vulnerable Oracle-Dependent Contract
;; Tests: unprotected mint, price oracle manipulation, time-lock bypass

(define-fungible-token oracle-token)
(define-data-var token-uri (string-utf8 256) u"https://example.com/token")
(define-data-var unlock-height uint u0)
(define-data-var price-per-token uint u1000000)

;; VULN: Unprotected mint - anyone can mint
(define-public (mint (amount uint) (recipient principal))
  (ft-mint? oracle-token amount recipient)
)

;; VULN: Uses price oracle without validation
(define-public (buy-tokens (stx-amount uint))
  (let ((price (get-price)))
    (try! (stx-transfer? stx-amount tx-sender (as-contract tx-sender)))
    (ft-mint? oracle-token (/ stx-amount price) tx-sender)
  )
)

(define-read-only (get-price)
  (var-get price-per-token)
)

;; VULN: Public time-lock setter
(define-public (set-unlock-height (new-height uint))
  (begin
    (var-set unlock-height new-height)
    (ok true)
  )
)

(define-public (withdraw (amount uint))
  (begin
    (asserts! (>= block-height (var-get unlock-height)) (err u403))
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)
