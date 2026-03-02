;; vulnerable-v4.clar — Test contract for detectors #61-65

(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_NOT_APPROVED (err u402))

(define-fungible-token vuln-token)

(define-data-var contract-owner principal tx-sender)
(define-data-var announcement (string-ascii 128) "")

(define-map profiles {user: principal} {nickname: (string-ascii 40)})
(define-map proposals uint {target: principal, amount: uint, approved: bool})

(define-trait payout-trait
  (
    (pay (uint principal) (response bool uint))
  )
)

;; #61: Unbounded map-set in public function (state bloat DoS)
(define-public (store-profile (user principal) (nickname (string-ascii 40)))
  (begin
    (map-set profiles {user: user} {nickname: nickname})
    (ok true)))

;; #63: Unsafe string concatenation without length check
(define-public (set-announcement (part-a (string-ascii 80)) (part-b (string-ascii 80)))
  (begin
    (var-set announcement (concat part-a part-b))
    (ok true)))

;; #64: Governance proposal execution without timelock
(define-public (execute-proposal (proposal-id uint))
  (let ((proposal (unwrap-panic (map-get? proposals proposal-id))))
    (begin
      (asserts! (get approved proposal) ERR_NOT_APPROVED)
      (stx-transfer? (get amount proposal) (as-contract tx-sender) (get target proposal))
      (ok true))))

;; #65: Unvalidated trait parameter in public function
(define-public (forward-call (adapter <payout-trait>) (amount uint) (recipient principal))
  (contract-call? adapter pay amount recipient))

;; Intentionally missing SIP-010 metadata functions get-symbol/get-decimals for #62.
