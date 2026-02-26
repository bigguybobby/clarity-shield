;; Test contract: Flash loan vulnerability patterns
;; Expected findings: flash loan, unbounded loops, missing events

(define-data-var admin principal tx-sender)
(define-map balances principal uint)
(define-map prices (string-ascii 10) uint)

;; Flash loan pattern: reads balance then transfers
(define-public (swap-tokens (amount uint) (recipient principal))
  (let ((current-balance (stx-get-balance tx-sender))
        (price (default-to u0 (map-get? prices "STX"))))
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (stx-transfer? amount tx-sender recipient)
  )
)

;; Unbounded iteration with fold
(define-public (process-batch (items (list 200 uint)))
  (ok (fold sum-item items u0))
)

(define-private (sum-item (item uint) (acc uint))
  (+ item acc)
)

;; Missing event logging: state change without print
(define-public (update-price (token (string-ascii 10)) (new-price uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (map-set prices token new-price)
    (ok true)
  )
)

;; Good function: has event logging
(define-public (update-balance (user principal) (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u401))
    (map-set balances user amount)
    (print { event: "balance-updated", user: user, amount: amount })
    (ok true)
  )
)
