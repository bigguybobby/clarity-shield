;; Test contract for #82 Missing Emergency Mechanism detector
;; VULNERABLE: DeFi contract with 4 financial ops and NO halt/stop logic

(define-data-var admin principal tx-sender)
(define-data-var fee-rate uint u100)

;; Transfer with no guard
(define-public (swap-tokens (amount uint) (recipient principal))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)))

;; Another financial function, no guard
(define-public (provide-liquidity (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)))

;; Mint with no guard
(define-public (claim-rewards (amount uint))
  (begin
    (try! (ft-mint? reward-token amount tx-sender))
    (ok true)))

;; Burn with no guard
(define-public (burn-tokens (amount uint))
  (begin
    (try! (ft-burn? reward-token amount tx-sender))
    (ok true)))
