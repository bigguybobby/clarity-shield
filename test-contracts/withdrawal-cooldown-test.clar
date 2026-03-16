;; Test contract for detector #87: Missing Withdrawal Cooldown

;; --- Tokens ---
(define-fungible-token pool-token)
(define-data-var contract-owner principal tx-sender)

;; --- Error constants ---
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-COOLDOWN-ACTIVE (err u101))
(define-constant ERR-INSUFFICIENT-BALANCE (err u102))

;; --- Constants ---
(define-constant MIN-LOCK-PERIOD u144) ;; ~1 day of blocks

;; --- State ---
(define-map positions
  principal
  { amount: uint, deposit-block: uint }
)

(define-map simple-balances principal uint)

;; ============================================================
;; VULNERABLE: withdraw without any cooldown check
;; ============================================================
(define-public (deposit (amount uint))
  (begin
    (map-set simple-balances tx-sender
      (+ (default-to u0 (map-get? simple-balances tx-sender)) amount))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

(define-public (withdraw (amount uint))
  (let ((balance (default-to u0 (map-get? simple-balances tx-sender))))
    (asserts! (>= balance amount) ERR-INSUFFICIENT-BALANCE)
    (map-set simple-balances tx-sender (- balance amount))
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; VULNERABLE: unstake without time lock
;; ============================================================
(define-public (stake (amount uint))
  (begin
    (map-set positions tx-sender { amount: amount, deposit-block: block-height })
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

(define-public (unstake (amount uint))
  (let ((pos (unwrap! (map-get? positions tx-sender) ERR-INSUFFICIENT-BALANCE)))
    (map-set positions tx-sender
      { amount: (- (get amount pos) amount), deposit-block: (get deposit-block pos) })
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; SAFE: withdraw with block-height cooldown check
;; ============================================================
(define-public (exit-pool (amount uint))
  (let ((pos (unwrap! (map-get? positions tx-sender) ERR-INSUFFICIENT-BALANCE)))
    (asserts! (>= (- block-height (get deposit-block pos)) MIN-LOCK-PERIOD) ERR-COOLDOWN-ACTIVE)
    (map-set positions tx-sender
      { amount: (- (get amount pos) amount), deposit-block: (get deposit-block pos) })
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; SAFE: redeem with cooldown variable reference
;; ============================================================
(define-data-var cooldown-blocks uint u200)

(define-public (redeem (amount uint))
  (let ((pos (unwrap! (map-get? positions tx-sender) ERR-INSUFFICIENT-BALANCE))
        (cooldown (var-get cooldown-blocks)))
    (asserts! (>= (- block-height (get deposit-block pos)) cooldown) ERR-COOLDOWN-ACTIVE)
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; SAFE: remove-liquidity with lock-period check
;; ============================================================
(define-constant LOCK-PERIOD u500)

(define-public (remove-liquidity (amount uint))
  (let ((pos (unwrap! (map-get? positions tx-sender) ERR-INSUFFICIENT-BALANCE)))
    (asserts! (>= (- block-height (get deposit-block pos)) LOCK-PERIOD) ERR-COOLDOWN-ACTIVE)
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)

;; ============================================================
;; SAFE: claim-and-withdraw with unbonding reference
;; ============================================================
(define-map unbonding-requests principal { amount: uint, unbonding-start: uint })

(define-public (claim-and-withdraw (amount uint))
  (let ((req (unwrap! (map-get? unbonding-requests tx-sender) ERR-NOT-AUTHORIZED)))
    (asserts! (>= (- block-height (get unbonding-start req)) MIN-LOCK-PERIOD) ERR-COOLDOWN-ACTIVE)
    (as-contract (stx-transfer? amount tx-sender tx-sender))
  )
)
