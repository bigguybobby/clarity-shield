;; Test contract for detector #72 — Missing Token Supply Cap

(define-fungible-token uncapped-token)
(define-fungible-token capped-token)

(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-SUPPLY u1000000)
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_CAP_EXCEEDED (err u402))

;; BAD: Public mint with no supply cap — should trigger #72
(define-public (mint-uncapped (amount uint) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR_UNAUTHORIZED)
    (ft-mint? uncapped-token amount recipient)
  )
)

;; GOOD: Public mint with max-supply check — should NOT trigger #72
(define-public (mint-capped (amount uint) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR_UNAUTHORIZED)
    (asserts! (<= (+ (ft-get-supply capped-token) amount) MAX-SUPPLY) ERR_CAP_EXCEEDED)
    (ft-mint? capped-token amount recipient)
  )
)

;; BAD: Claim/airdrop function that mints without cap — should trigger #72
(define-public (claim-airdrop)
  (begin
    (ft-mint? uncapped-token u100 tx-sender)
  )
)

;; GOOD: Mint with supply-cap in function body — should NOT trigger #72
(define-public (mint-with-cap-keyword (amount uint))
  (let ((supply-cap u500000))
    (asserts! (<= amount supply-cap) ERR_CAP_EXCEEDED)
    (ft-mint? capped-token amount tx-sender)
  )
)

;; GOOD: read-only function — not public, should NOT trigger
(define-read-only (get-total-supply)
  (ft-get-supply capped-token)
)
