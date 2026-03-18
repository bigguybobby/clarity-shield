;; Test contract for #93 Unsafe at-block Usage detector

;; ==============================
;; VULNERABLE: at-block with user-supplied block hash in public function
;; ==============================

;; Vulnerable #1: public function passes user-supplied block-hash directly to at-block
(define-public (get-historical-balance (user principal) (block-hash (buff 32)))
  (ok (at-block block-hash (stx-get-balance user)))
)

;; Vulnerable #2: public function uses parameter in at-block for token lookup
(define-public (get-past-price (block-hash (buff 32)))
  (ok (at-block block-hash (var-get current-price)))
)

;; ==============================
;; SAFE: at-block with validated/hardcoded block hash
;; ==============================

;; Data vars for safe patterns
(define-data-var current-price uint u0)
(define-data-var trusted-block-hash (buff 32) 0x0000000000000000000000000000000000000000000000000000000000000000)
(define-data-var last-snapshot-height uint u0)

;; Safe #1: uses a stored/trusted block hash, not user input
(define-public (get-snapshot-balance (user principal))
  (ok (at-block (var-get trusted-block-hash) (stx-get-balance user)))
)

;; Safe #2: at-block used in read-only function (no state mutation risk)
(define-read-only (read-historical-balance (user principal) (block-hash (buff 32)))
  (at-block block-hash (stx-get-balance user))
)

;; Safe #3: at-block in private function (not directly callable)
(define-private (internal-lookup (block-hash (buff 32)))
  (at-block block-hash (var-get current-price))
)

;; Safe #4: public function with block height validation before at-block
(define-public (get-recent-balance (user principal) (block-hash (buff 32)) (block-height-param uint))
  (begin
    (asserts! (>= block-height-param (- block-height u100)) (err u401))
    (ok (at-block block-hash (stx-get-balance user)))
  )
)

;; ==============================
;; NON-RELEVANT: no at-block usage
;; ==============================

;; No at-block, should not trigger
(define-public (simple-transfer (amount uint) (recipient principal))
  (stx-transfer? amount tx-sender recipient)
)
