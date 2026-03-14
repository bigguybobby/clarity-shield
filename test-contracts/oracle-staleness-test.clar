;; Test contract for stale oracle price dependency detector (#80)

;; --- Data Variables ---
(define-data-var contract-owner principal tx-sender)
(define-data-var current-price uint u0)
(define-data-var last-update-block uint u0)
(define-data-var oracle-rate uint u0)

;; --- VULNERABLE: External oracle call without freshness check ---
(define-public (liquidate-position (user principal) (amount uint))
  (let
    ((price (unwrap! (contract-call? .price-oracle get-price "STX-USD") (err u1))))
    ;; Uses price directly without checking if it's stale
    (if (< (* amount price) u1000000)
      (stx-transfer? amount user (as-contract tx-sender))
      (ok true)
    )
  )
)

;; --- VULNERABLE: Price variable read without freshness in financial op ---
(define-public (borrow-against-collateral (amount uint))
  (let
    ((price (var-get current-price)))
    ;; Uses stored price but never checks when it was last updated
    (if (> (* amount price) u500000)
      (begin
        (try! (ft-mint? lending-token amount tx-sender))
        (ok true)
      )
      (err u2)
    )
  )
)

;; --- SAFE: External oracle call WITH freshness validation ---
(define-public (safe-liquidate (user principal) (amount uint))
  (let
    ((price (unwrap! (contract-call? .price-oracle get-price "STX-USD") (err u1)))
     (last-update (var-get last-update-block)))
    ;; Validates freshness: price must be updated within last 10 blocks
    (asserts! (<= (- block-height last-update) u10) (err u100))
    (if (< (* amount price) u1000000)
      (stx-transfer? amount user (as-contract tx-sender))
      (ok true)
    )
  )
)

;; --- SAFE: Uses timestamp/staleness check ---
(define-public (safe-borrow (amount uint))
  (let
    ((price (var-get current-price))
     (price-age (- block-height (var-get last-update-block))))
    ;; Staleness check
    (asserts! (< price-age u20) (err u200))
    (if (> (* amount price) u500000)
      (begin
        (try! (ft-mint? lending-token amount tx-sender))
        (ok true)
      )
      (err u2)
    )
  )
)

;; --- SAFE: Read-only price check (no financial operations) ---
(define-public (check-price-info)
  (let
    ((price (var-get oracle-rate)))
    ;; Just reads and returns — no transfers, mints, or burns
    (ok price)
  )
)
