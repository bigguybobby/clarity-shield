;; Vulnerable Governance Contract - Tests detectors #41-45

;; #45: Single owner governance (no multisig)
(define-data-var contract-owner principal tx-sender)

(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set contract-owner new-owner)
    (ok true)))

;; #41: Unchecked to-uint conversion
(define-public (deposit (amount int))
  (let ((converted (to-uint amount)))
    (stx-transfer? converted tx-sender (as-contract tx-sender))))

;; #41: Unchecked to-int conversion
(define-read-only (get-signed-balance (bal uint))
  (to-int bal))

;; #42: Balance-dependent logic with transfer
(define-public (withdraw-all)
  (let ((balance (stx-get-balance (as-contract tx-sender))))
    (stx-transfer? balance (as-contract tx-sender) tx-sender)))

;; #43: Unvalidated callback function
(define-public (callback-on-transfer (amount uint) (sender principal))
  (begin
    (print {event: "transfer-callback", amount: amount})
    (ok true)))

;; #43: Another unvalidated hook
(define-public (handle-price-update (new-price uint))
  (begin
    (var-set last-price new-price)
    (ok true)))

(define-data-var last-price uint u0)

;; #44: Large string parameter
(define-public (set-metadata (data (string-utf8 4096)))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (ok true)))
