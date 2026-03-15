;; Test contract for detector #85 - Missing Minimum Deposit Amount

;; Tokens and maps
(define-fungible-token pool-token)
(define-data-var total-staked uint u0)
(define-map user-deposits principal uint)
(define-map user-stakes { staker: principal } { amount: uint, block: uint })
(define-constant ERR-BELOW-MINIMUM (err u500))
(define-constant MIN-DEPOSIT u1000000)
(define-constant contract-owner tx-sender)

;; VULNERABLE: deposit without minimum amount check
(define-public (deposit (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set user-deposits tx-sender amount)
    (ok true)
  )
)

;; VULNERABLE: stake without minimum check
(define-public (stake (amount uint))
  (begin
    (try! (ft-transfer? pool-token amount tx-sender (as-contract tx-sender)))
    (map-set user-stakes { staker: tx-sender } { amount: amount, block: block-height })
    (ok true)
  )
)

;; VULNERABLE: add-liquidity without minimum
(define-public (add-liquidity (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (var-set total-staked (+ (var-get total-staked) amount))
    (ok true)
  )
)

;; SAFE: deposit with minimum amount enforcement
(define-public (deposit-safe (amount uint))
  (begin
    (asserts! (>= amount MIN-DEPOSIT) ERR-BELOW-MINIMUM)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set user-deposits tx-sender amount)
    (ok true)
  )
)

;; SAFE: stake with min-stake constant check
(define-public (stake-safe (amount uint))
  (let ((min-stake u500000))
    (asserts! (>= amount min-stake) (err u501))
    (try! (ft-transfer? pool-token amount tx-sender (as-contract tx-sender)))
    (map-set user-stakes { staker: tx-sender } { amount: amount, block: block-height })
    (ok true)
  )
)

;; SAFE: provide-liquidity with min-amount check
(define-public (provide-liquidity (amount uint))
  (begin
    (asserts! (>= amount u100000) (err u502))
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (var-set total-staked (+ (var-get total-staked) amount))
    (ok true)
  )
)

;; NOT A DEPOSIT FUNCTION: should not be flagged
(define-public (transfer-tokens (amount uint) (recipient principal))
  (begin
    (try! (stx-transfer? amount tx-sender recipient))
    (ok true)
  )
)
