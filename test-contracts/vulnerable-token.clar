;; Vulnerable Token Contract
;; Contains multiple security issues for testing Clarity Shield

(define-fungible-token vulnerable-token)

;; VULN: Hardcoded principal (centralization risk)
(define-data-var contract-owner principal 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
(define-data-var paused bool false)

;; VULN: Missing authorization on critical function
(define-public (mint (amount uint) (recipient principal))
  ;; NO authorization check - anyone can mint tokens!
  (ft-mint? vulnerable-token amount recipient))

;; VULN: contract-caller used for authorization (can be bypassed)
(define-public (set-owner (new-owner principal))
  (begin
    ;; WRONG: should use tx-sender, not contract-caller
    (asserts! (is-eq contract-caller (var-get contract-owner)) (err u403))
    (ok (var-set contract-owner new-owner))))

;; VULN: Unchecked arithmetic (overflow risk)
(define-public (unsafe-transfer (amount uint) (recipient principal))
  (let (
    (sender-balance (ft-get-balance vulnerable-token tx-sender))
    ;; VULN: No overflow check on addition
    (recipient-balance (+ (ft-get-balance vulnerable-token recipient) amount))
  )
    (try! (ft-transfer? vulnerable-token amount tx-sender recipient))
    (ok true)))

;; VULN: unwrap-panic can cause DoS
(define-public (burn (amount uint))
  (begin
    ;; VULN: If burn fails, entire transaction panics
    (unwrap-panic (ft-burn? vulnerable-token amount tx-sender))
    (ok true)))

;; VULN: No response handling from contract call
(define-public (call-external-contract (contract principal))
  (begin
    ;; VULN: Response not handled - silent failure possible
    (contract-call? contract external-function)
    (ok true)))

(define-read-only (get-balance (account principal))
  (ok (ft-get-balance vulnerable-token account)))

(define-read-only (get-owner)
  (ok (var-get contract-owner)))
