;; Test contract for Unvalidated Price Oracle Update detector

;; VULNERABLE #1: Direct price update with no controls
(define-data-var current-price uint u0)

(define-public (set-price (new-price uint))
  (begin
    (var-set current-price new-price)
    (ok true)))

;; VULNERABLE #2: Oracle update with only owner check (no bounds)
(define-data-var contract-owner principal tx-sender)
(define-data-var btc-price uint u40000)

(define-public (update-btc-price (price uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set btc-price price)
    (ok true)))

;; SAFE #1: Price update with deviation bounds
(define-data-var safe-price uint u1000)
(define-constant MAX-DEVIATION u100) ;; 10%

(define-public (update-price-with-bounds (new-price uint))
  (let ((old-price (var-get safe-price)))
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (asserts! (<= (if (> new-price old-price)
                      (- new-price old-price)
                      (- old-price new-price))
                  (/ (* old-price MAX-DEVIATION) u1000))
              (err u402))
    (var-set safe-price new-price)
    (ok true)))

;; SAFE #2: Price update with timelock
(define-data-var proposed-price uint u0)
(define-data-var proposal-time uint u0)
(define-constant TIMELOCK-BLOCKS u144) ;; ~24 hours

(define-public (propose-price (price uint))
  (begin
    (var-set proposed-price price)
    (var-set proposal-time block-height)
    (ok true)))

(define-public (execute-price-update)
  (begin
    (asserts! (>= (- block-height (var-get proposal-time)) TIMELOCK-BLOCKS) (err u403))
    (var-set current-price (var-get proposed-price))
    (ok true)))

;; SAFE #3: Multi-sig price update
(define-map price-updates uint {price: uint, confirmations: uint})
(define-data-var update-nonce uint u0)

(define-public (confirm-price-update (update-id uint) (price uint))
  (let ((current-update (default-to {price: u0, confirmations: u0}
                                     (map-get? price-updates update-id))))
    (map-set price-updates update-id
      {price: price, confirmations: (+ (get confirmations current-update) u1)})
    (if (>= (get confirmations current-update) u2)
        (var-set current-price price)
        false)
    (ok true)))

;; NON-ORACLE: Regular setter (not price-related)
(define-data-var user-balance uint u0)

(define-public (set-balance (amount uint))
  (begin
    (var-set user-balance amount)
    (ok true)))
