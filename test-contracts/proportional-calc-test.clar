;; Test contract for Unsafe Proportional Calculation detector (#86)

;; --- Data Variables ---
(define-data-var total-deposits uint u0)
(define-data-var total-shares uint u0)
(define-data-var total-staked uint u0)
(define-fungible-token pool-token)

;; --- VULNERABLE: Division by var-get total-deposits without zero check ---
(define-public (deposit-shares (amount uint))
  (let
    (
      (user-shares (/ (* amount (var-get total-shares)) (var-get total-deposits)))
    )
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (var-set total-deposits (+ (var-get total-deposits) amount))
    (var-set total-shares (+ (var-get total-shares) user-shares))
    (ok user-shares)
  )
)

;; --- VULNERABLE: Division by ft-get-supply without zero check ---
(define-public (calculate-reward (amount uint))
  (let
    (
      (reward (/ (* amount u1000) (ft-get-supply pool-token)))
    )
    (try! (ft-mint? pool-token reward tx-sender))
    (ok reward)
  )
)

;; --- VULNERABLE: Division by var-get total-staked without zero check ---
(define-public (claim-proportional (user-stake uint))
  (let
    (
      (share (/ (* user-stake u10000) (var-get total-staked)))
    )
    (try! (stx-transfer? share (as-contract tx-sender) tx-sender))
    (ok share)
  )
)

;; --- SAFE: Has zero check with asserts! before division ---
(define-public (safe-deposit (amount uint))
  (begin
    (asserts! (> (var-get total-deposits) u0) (err u100))
    (let
      (
        (user-shares (/ (* amount (var-get total-shares)) (var-get total-deposits)))
      )
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      (var-set total-deposits (+ (var-get total-deposits) amount))
      (var-set total-shares (+ (var-get total-shares) user-shares))
      (ok user-shares)
    )
  )
)

;; --- SAFE: Has if-branch for zero case (first deposit) ---
(define-public (safe-deposit-with-branch (amount uint))
  (if (is-eq (var-get total-deposits) u0)
    ;; First deposit: 1:1 ratio
    (begin
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      (var-set total-deposits amount)
      (var-set total-shares amount)
      (ok amount)
    )
    ;; Proportional calculation
    (let
      (
        (user-shares (/ (* amount (var-get total-shares)) (var-get total-deposits)))
      )
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      (var-set total-deposits (+ (var-get total-deposits) amount))
      (var-set total-shares (+ (var-get total-shares) user-shares))
      (ok user-shares)
    )
  )
)

;; --- SAFE: Division by constant, not a mutable variable ---
(define-public (calculate-fee (amount uint))
  (let
    (
      (fee (/ (* amount u3) u1000))
    )
    (try! (stx-transfer? fee tx-sender (as-contract tx-sender)))
    (ok fee)
  )
)

;; --- NOT RELEVANT: No division at all ---
(define-public (simple-transfer (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (ok true)
  )
)
