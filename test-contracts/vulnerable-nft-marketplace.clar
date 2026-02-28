;; Vulnerable NFT Marketplace Contract
;; This contract demonstrates issues detected by the new v1.6.0 detectors

(define-non-fungible-token marketplace-nft uint)

(define-data-var nft-counter uint u0)
(define-data-var marketplace-fee uint u25) ;; 2.5% fee
(define-data-var contract-owner principal tx-sender)

;; ISSUE #32: Unchecked cross-contract call
;; This function calls an external contract without checking the return value
(define-public (transfer-to-vault (nft-id uint) (vault-contract principal))
    (begin
        ;; No try! or unwrap! wrapping - could silently fail
        (contract-call? vault-contract store-nft nft-id)
        (ok true)
    )
)

;; ISSUE #33: Redundant authorization checks
;; This function checks BOTH tx-sender AND contract-caller against owner
(define-public (update-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) (err u401))
        (asserts! (is-eq contract-caller (var-get contract-owner)) (err u402))
        (var-set marketplace-fee new-fee)
        (ok true)
    )
)

;; ISSUE #34: Unprotected burn function
;; Anyone can call this to burn NFTs
(define-public (burn-nft (nft-id uint))
    (begin
        (nft-burn? marketplace-nft nft-id tx-sender)
    )
)

;; ISSUE #35: Missing SIP-009 compliance
;; This NFT contract is missing required SIP-009 functions:
;; - get-last-token-id (missing)
;; - get-token-uri (missing)
;; - get-owner (missing)
;; - transfer (missing)

;; Only has mint, which is not enough for SIP-009 compliance
(define-public (mint-nft (recipient principal))
    (let ((nft-id (var-get nft-counter)))
        (try! (nft-mint? marketplace-nft nft-id recipient))
        (var-set nft-counter (+ nft-id u1))
        (ok nft-id)
    )
)

;; Unsafe listing function with unchecked external call
(define-public (list-nft-with-oracle (nft-id uint) (price-oracle principal))
    (begin
        ;; ISSUE #32: Another unchecked cross-contract call
        (contract-call? price-oracle get-floor-price)
        (ok true)
    )
)
