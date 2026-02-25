;; Vulnerable Vault Contract
;; Stores STX with multiple security flaws

(define-map balances principal uint)
(define-map admin-roles principal bool)

;; VULN: Hardcoded admin
(define-constant ADMIN 'SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE)

;; VULN: Missing authorization check on deposit
(define-public (deposit (amount uint))
  ;; Anyone can deposit to anyone's balance!
  (begin
    ;; VULN: map-set without validation of existing balance
    (map-set balances tx-sender amount)
    (stx-transfer? amount tx-sender (as-contract tx-sender))))

;; VULN: Unsafe unwrap on withdrawal
(define-public (withdraw (amount uint))
  (let (
    ;; VULN: map-get? without default-to
    (balance (map-get? balances tx-sender))
  )
    ;; VULN: unwrap! without proper error handling
    (asserts! (>= (unwrap! balance (err u404)) amount) (err u400))
    (map-set balances tx-sender (- (unwrap! balance (err u404)) amount))
    (as-contract (stx-transfer? amount tx-sender tx-sender))))

;; VULN: contract-caller in auth check (bypassable)
(define-public (emergency-withdraw (user principal))
  (begin
    ;; VULN: Using contract-caller instead of tx-sender
    (asserts! (is-eq contract-caller ADMIN) (err u403))
    (let ((user-balance (default-to u0 (map-get? balances user))))
      (map-delete balances user)
      (as-contract (stx-transfer? user-balance tx-sender user)))))

;; VULN: Arithmetic without overflow check
(define-public (compound-interest (user principal) (rate uint))
  (let (
    (current-balance (default-to u0 (map-get? balances user)))
    ;; VULN: Multiplication without overflow protection
    (interest (* current-balance rate))
    ;; VULN: Addition without overflow protection
    (new-balance (+ current-balance interest))
  )
    (map-set balances user new-balance)
    (ok new-balance)))

(define-read-only (get-balance (user principal))
  (ok (default-to u0 (map-get? balances user))))
