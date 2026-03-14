;; Test contract for detector #81 — Unprotected Liquidity Withdrawal

;; ---- VULNERABLE: withdraw with no share enforcement, no timelock, no multisig ----

(define-data-var pool-balance uint u0)
(define-data-var admin principal tx-sender)

(define-public (withdraw-liquidity (amount uint) (recipient principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) (err u403))
        (try! (stx-transfer? amount (as-contract tx-sender) recipient))
        (ok true)
    )
)

(define-public (emergency-withdraw (amount uint))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) (err u403))
        (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
        (ok true)
    )
)

;; ---- SAFE: proportional LP token burn withdrawal ----

(define-fungible-token lp-token)
(define-data-var total-supply uint u0)

(define-public (remove-liquidity (lp-amount uint))
    (let (
        (user-share (/ (* lp-amount (var-get pool-balance)) (var-get total-supply)))
    )
        (try! (ft-burn? lp-token lp-amount tx-sender))
        (try! (stx-transfer? user-share (as-contract tx-sender) tx-sender))
        (var-set total-supply (- (var-get total-supply) lp-amount))
        (ok user-share)
    )
)

;; ---- SAFE: timelock-protected withdrawal ----

(define-data-var withdrawal-unlock-block uint u0)

(define-public (withdraw-pool (amount uint))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) (err u403))
        (asserts! (>= block-height (var-get withdrawal-unlock-block)) (err u100))
        (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
        (ok true)
    )
)

;; ---- SAFE: multi-sig governance withdrawal ----

(define-data-var required-approvals uint u3)
(define-data-var approval-count uint u0)

(define-public (admin-withdraw (amount uint))
    (begin
        (asserts! (>= (var-get approval-count) (var-get required-approvals)) (err u401))
        (try! (stx-transfer? amount (as-contract tx-sender) tx-sender))
        (var-set approval-count u0)
        (ok true)
    )
)
