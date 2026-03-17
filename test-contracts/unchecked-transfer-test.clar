;; Unchecked Transfer Return Value Test Contract
;;
;; Tests detector #90: Unchecked Transfer Return Value
;;
;; Vulnerable: Functions that call transfer functions without checking return values
;; Safe: Functions that use try!, unwrap!, asserts!, or match to check transfers

(define-constant ERR-TRANSFER-FAILED (err u100))
(define-constant ERR-INSUFFICIENT-BALANCE (err u101))

(define-map balances principal uint)
(define-data-var total-supply uint u0)

;; VULNERABLE #1: Unchecked STX transfer
(define-public (withdraw-unchecked (amount uint) (recipient principal))
  (begin
    ;; Transfer is called but return value is ignored
    (stx-transfer? amount tx-sender recipient)
    ;; State is updated even if transfer failed!
    (map-set balances tx-sender 
      (- (default-to u0 (map-get? balances tx-sender)) amount))
    (ok true)
  )
)

;; VULNERABLE #2: Unchecked FT transfer in escrow release
(define-public (release-escrow-unchecked (token <ft-trait>) (amount uint) (to principal))
  (begin
    ;; Transfer called without checking result
    (contract-call? token transfer amount tx-sender to none)
    ;; Escrow is marked as released even if transfer failed
    (map-delete balances to)
    (ok true)
  )
)

;; VULNERABLE #3: Unchecked NFT transfer
(define-public (claim-nft-unchecked (token-id uint) (owner principal) (buyer principal))
  (begin
    ;; NFT transfer not checked
    (nft-transfer? my-nft token-id owner buyer)
    ;; Payment processed even if NFT transfer failed
    (stx-transfer? u1000000 buyer owner)
    (ok true)
  )
)

;; SAFE #1: Using try! to check STX transfer
(define-public (withdraw-safe-try (amount uint) (recipient principal))
  (begin
    ;; try! automatically propagates errors
    (try! (stx-transfer? amount tx-sender recipient))
    ;; Only reaches here if transfer succeeded
    (map-set balances tx-sender 
      (- (default-to u0 (map-get? balances tx-sender)) amount))
    (ok true)
  )
)

;; SAFE #2: Using unwrap! to check FT transfer
(define-public (release-escrow-safe-unwrap (token <ft-trait>) (amount uint) (to principal))
  (begin
    ;; unwrap! aborts with custom error if transfer fails
    (unwrap! (contract-call? token transfer amount tx-sender to none) ERR-TRANSFER-FAILED)
    ;; Only deletes escrow if transfer succeeded
    (map-delete balances to)
    (ok true)
  )
)

;; SAFE #3: Using asserts! to check NFT transfer
(define-public (claim-nft-safe-asserts (token-id uint) (owner principal) (buyer principal))
  (begin
    ;; asserts! checks the transfer succeeded
    (asserts! (is-ok (nft-transfer? my-nft token-id owner buyer)) ERR-TRANSFER-FAILED)
    ;; Payment only processed if NFT transfer succeeded
    (try! (stx-transfer? u1000000 buyer owner))
    (ok true)
  )
)

;; SAFE #4: Using match for explicit error handling
(define-public (withdraw-safe-match (amount uint) (recipient principal))
  (match (stx-transfer? amount tx-sender recipient)
    success (begin
      ;; Transfer succeeded, update state
      (map-set balances tx-sender 
        (- (default-to u0 (map-get? balances tx-sender)) amount))
      (ok true)
    )
    error (err ERR-TRANSFER-FAILED)
  )
)

;; SAFE #5: Let binding with subsequent check
(define-public (withdraw-safe-let (amount uint) (recipient principal))
  (let ((transfer-result (stx-transfer? amount tx-sender recipient)))
    (asserts! (is-ok transfer-result) ERR-TRANSFER-FAILED)
    (map-set balances tx-sender 
      (- (default-to u0 (map-get? balances tx-sender)) amount))
    (ok true)
  )
)

;; Non-transfer function (should not be flagged)
(define-public (get-balance (account principal))
  (ok (default-to u0 (map-get? balances account)))
)

;; Trait definitions (for completeness)
(define-trait ft-trait
  ((transfer (uint principal principal (optional (buff 34))) (response bool uint)))
)

(define-non-fungible-token my-nft uint)
