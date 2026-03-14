;; Safe test contract for #82 — has pause mechanism

(define-data-var admin principal tx-sender)
(define-data-var is-paused bool false)

(define-constant ERR-PAUSED (err u1000))

;; Pause control
(define-public (pause-contract)
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (var-set is-paused true)
    (ok true)))

(define-public (unpause-contract)
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (var-set is-paused false)
    (ok true)))

;; Safe: financial ops with pause check
(define-public (swap-tokens (amount uint) (recipient principal))
  (begin
    (asserts! (not (var-get is-paused)) ERR-PAUSED)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)))

(define-public (provide-liquidity (amount uint))
  (begin
    (asserts! (not (var-get is-paused)) ERR-PAUSED)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)))

(define-public (claim-rewards (amount uint))
  (begin
    (asserts! (not (var-get is-paused)) ERR-PAUSED)
    (try! (ft-mint? reward-token amount tx-sender))
    (ok true)))
