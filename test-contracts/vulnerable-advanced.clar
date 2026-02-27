;; vulnerable-advanced.clar — Test contract for advanced detectors

;; NFT definition
(define-non-fungible-token cool-nft uint)
(define-data-var last-id uint u0)

;; BUG: NFT transfer without ownership check
(define-public (transfer-nft (id uint) (recipient principal))
    (nft-transfer? cool-nft id tx-sender recipient)
)

;; BUG: map-delete without existence check
(define-map listings { id: uint } { price: uint, seller: principal })
(define-public (cancel-listing (id uint))
    (begin
        (map-delete listings { id: id })
        (ok true)
    )
)

;; BUG: balance-dependent logic
(define-public (whale-only-action)
    (begin
        (asserts! (>= (stx-get-balance tx-sender) u1000000) (err u403))
        (ok true)
    )
)

;; BUG: deprecated get-block-info?
(define-read-only (get-miner (height uint))
    (get-block-info? miner-address height)
)

;; BUG: raw error codes everywhere, no constants
(define-public (do-something (x uint))
    (begin
        (asserts! (> x u0) (err u1))
        (asserts! (< x u100) (err u2))
        (asserts! (is-eq tx-sender 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM) (err u3))
        (ok x)
    )
)
