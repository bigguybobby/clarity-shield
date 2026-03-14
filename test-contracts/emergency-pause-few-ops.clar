;; Safe test contract for #82 — only 2 financial ops (below threshold)

(define-data-var admin principal tx-sender)

;; Only 2 financial functions — should NOT trigger #82
(define-public (transfer-funds (amount uint) (recipient principal))
  (begin
    (try! (stx-transfer? amount tx-sender recipient))
    (ok true)))

(define-public (mint-token (amount uint))
  (begin
    (try! (ft-mint? my-token amount tx-sender))
    (ok true)))

;; Non-financial public function
(define-public (set-name (new-name (string-ascii 50)))
  (ok true))
