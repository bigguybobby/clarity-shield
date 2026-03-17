;; Test contract for detector #88: Unprotected Liquidation
;; Tests: 2 vulnerable + 4 safe functions

;; --- Setup: Price oracle and lending state ---
(define-data-var current-price uint u100000000)
(define-data-var price-deviation-threshold uint u500) ;; 5%
(define-data-var last-updated uint u0)
(define-data-var grace-period uint u144) ;; ~1 day in blocks

(define-map loans
  { borrower: principal }
  { collateral: uint, debt: uint, deposit-block: uint }
)

(define-map oracle-prices
  { source: uint }
  { price: uint }
)

;; External oracle call pattern
(define-private (get-price)
  (var-get current-price)
)

;; VULNERABLE #1: Liquidation with no protections at all
(define-public (liquidate (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (price (get-price))
    (collateral-value (* (get collateral loan) price))
  )
    (stx-transfer? (get collateral loan) borrower tx-sender)
  )
)

;; VULNERABLE #2: Liquidation with price read but no deviation/health checks
(define-public (force-close (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (price (get-price))
  )
    (try! (stx-transfer? (get collateral loan) borrower tx-sender))
    (ok true)
  )
)

;; SAFE #1: Has price deviation threshold check
(define-public (liquidate-with-deviation-check (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (price (get-price))
    (price-deviation (/ (* (- price (var-get current-price)) u10000) (var-get current-price)))
  )
    (asserts! (< price-deviation (var-get price-deviation-threshold)) (err u2))
    (stx-transfer? (get collateral loan) borrower tx-sender)
  )
)

;; SAFE #2: Has TWAP / time-weighted pricing
(define-public (liquidate-twap (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (twap-price (get-price))
  )
    (stx-transfer? (get collateral loan) borrower tx-sender)
  )
)

;; SAFE #3: Has grace period before liquidation
(define-public (liquidate-with-grace (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (price (get-price))
    (grace-period-blocks (var-get grace-period))
  )
    (stx-transfer? (get collateral loan) borrower tx-sender)
  )
)

;; SAFE #4: Has health factor / collateral ratio validation  
(define-public (liquidate-healthy-check (borrower principal))
  (let (
    (loan (unwrap! (map-get? loans { borrower: borrower }) (err u1)))
    (price (get-price))
    (collateral-value (* (get collateral loan) price))
    (health-factor (/ collateral-value (get debt loan)))
  )
    (asserts! (< health-factor u150) (err u3))
    (stx-transfer? (get collateral loan) borrower tx-sender)
  )
)

;; NON-LIQUIDATION: Should not be flagged
(define-public (deposit (amount uint))
  (stx-transfer? amount tx-sender (as-contract tx-sender))
)
