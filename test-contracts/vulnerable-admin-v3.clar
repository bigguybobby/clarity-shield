;; vulnerable-admin-v3.clar — Test contract for detectors #51-55

(define-data-var contract-owner principal tx-sender)
(define-data-var fee-rate uint u100)
(define-data-var treasury principal tx-sender)
(define-data-var total-distributed uint u0)

(define-fungible-token admin-token)
(define-map balances principal uint)
(define-map pending-payouts principal uint)

;; #51: Unprotected critical variable setter — no auth check
(define-public (set-treasury (new-treasury principal))
  (begin
    (var-set treasury new-treasury)
    (ok true)))

(define-public (update-fee-rate (new-fee uint))
  (begin
    (var-set fee-rate new-fee)
    (ok true)))

;; #52: Missing error branch — conditional but always returns ok
(define-public (process-claim (amount uint))
  (let ((balance (default-to u0 (map-get? balances tx-sender))))
    (if (>= balance amount)
      (begin
        (map-set balances tx-sender (- balance amount))
        (ok amount))
      (ok u0))))

;; #53: List append inside fold — unbounded growth
(define-public (collect-active-users (users (list 200 principal)))
  (let ((result (fold accumulate-user users (list))))
    (ok result)))

(define-private (accumulate-user (user principal) (acc (list 200 principal)))
  (if (is-some (map-get? balances user))
    (append acc user)
    acc))

;; #54: STX transfer inside fold — batch DoS risk
(define-public (batch-payout (recipients (list 50 principal)))
  (begin
    (fold payout-one recipients true)
    (ok true)))

(define-private (payout-one (recipient principal) (prev bool))
  (let ((amount (default-to u0 (map-get? pending-payouts recipient))))
    (if (> amount u0)
      (match (stx-transfer? amount (as-contract tx-sender) recipient)
        success true
        error false)
      prev)))

;; #55: Has set-admin and transfers but no pause mechanism
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (var-set contract-owner new-admin)
    (ok true)))

(define-public (withdraw (amount uint) (to principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
    (stx-transfer? amount (as-contract tx-sender) to)))
