;; Test contract for detector #74: Unbounded Reward Emission

;; ===== VULNERABLE FUNCTIONS =====

;; #1 Vulnerable: claim-rewards with no cooldown or tracking
(define-public (claim-rewards (amount uint))
  (begin
    (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
    (ok true)
  )
)

;; #2 Vulnerable: harvest-yield with ft-transfer but no guard
(define-public (harvest-yield (token-amount uint))
  (begin
    (try! (contract-call? .reward-token transfer token-amount (as-contract tx-sender) tx-sender none))
    (ok true)
  )
)

;; ===== SAFE FUNCTIONS =====

;; #3 Safe: claim with block-height cooldown
(define-map last-claimed principal uint)
(define-public (claim-daily (amount uint))
  (let ((last (default-to u0 (map-get? last-claimed tx-sender))))
    (asserts! (> block-height (+ last u144)) (err u1001))
    (map-set last-claimed tx-sender block-height)
    (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
    (ok true)
  )
)

;; #4 Safe: distribute-rewards with asserts! guard
(define-public (distribute-rewards (recipient principal) (amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u1000))
    (try! (stx-transfer? amount (as-contract tx-sender) recipient))
    (ok true)
  )
)

;; #5 Safe: non-reward function with transfer (should not trigger)
(define-public (send-payment (to principal) (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender to))
    (ok true)
  )
)
