;; Vulnerable Advanced V2 - Tests detectors #66-70

;; #66 - Public function with STX transfer but no post-condition annotation
(define-public (transfer-tokens (amount uint) (recipient principal))
  (begin
    (stx-transfer? amount tx-sender recipient)
  )
)

;; #67 - Dynamic dispatch via variable contract reference  
(define-public (execute-strategy (strategy-contract <strategy-trait>) (amount uint))
  (begin
    (contract-call? strategy-contract execute amount)
  )
)

;; #68 - NFT marketplace buy without royalty payment
(define-non-fungible-token cool-nft uint)
(define-map listings uint {price: uint, seller: principal})

(define-public (buy-nft (token-id uint))
  (let ((listing (unwrap! (map-get? listings token-id) (err u1)))
        (price (get price listing))
        (seller (get seller listing)))
    (try! (stx-transfer? price tx-sender seller))
    (try! (nft-transfer? cool-nft token-id seller tx-sender))
    (map-delete listings token-id)
    (ok true)
  )
)

;; #69 - Flash loan callback without sender verification
(define-public (on-flash-loan (amount uint) (fee uint) (data (buff 256)))
  (begin
    (try! (stx-transfer? (+ amount fee) tx-sender (as-contract tx-sender)))
    (ok true)
  )
)

;; #70 - Time-based unlock using block-height without comparison
(define-data-var unlock-height uint u0)

(define-public (unlock-funds (amount uint))
  (let ((current block-height))
    (var-set unlock-height current)
    (stx-transfer? amount (as-contract tx-sender) tx-sender)
  )
)
