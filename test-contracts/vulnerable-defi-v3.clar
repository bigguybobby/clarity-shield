;; vulnerable-defi-v3.clar — Test contract for detectors 56-60

;; Double-claim vulnerability: claim reads map but never deletes
(define-map rewards { user: principal } { amount: uint })

(define-public (claim-rewards)
  (let ((reward (unwrap! (map-get? rewards { user: tx-sender }) (err u404))))
    ;; BUG: never deletes or updates the map entry — can claim repeatedly
    (stx-transfer? (get amount reward) (as-contract tx-sender) tx-sender)
  )
)

;; Frontrunning: swap without slippage protection
(define-public (swap-tokens (amount uint))
  (begin
    ;; BUG: no min-amount-out or deadline parameter
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; Unchecked contract-call response
(define-public (bridge-transfer (amount uint) (recipient principal))
  (begin
    ;; BUG: contract-call result is not unwrapped or matched
    (contract-call? .token-contract transfer amount tx-sender recipient)
    (ok true)
  )
)

;; Unprotected callback
(define-public (on-transfer-complete (amount uint))
  (begin
    ;; BUG: no sender validation — anyone can call this callback
    (var-set last-transfer amount)
    (ok true)
  )
)

;; stx-liquid-supply usage
(define-read-only (get-share-price)
  (/ (* u1000000 (stx-get-balance (as-contract tx-sender))) stx-liquid-supply)
)

(define-data-var last-transfer uint u0)
