;; Test contract for detector #73 — Uncapped NFT Minting
;; Contains 2 vulnerable + 2 safe minting functions

(define-non-fungible-token cool-nft uint)
(define-data-var next-id uint u1)
(define-constant MAX-SUPPLY u10000)
(define-constant ERR_SOLD_OUT (err u100))
(define-constant ERR_NOT_AUTHORIZED (err u101))
(define-map mint-count principal uint)

;; VULNERABLE: no supply cap, no per-address limit
(define-public (mint-free)
  (let ((id (var-get next-id)))
    (try! (nft-mint? cool-nft id tx-sender))
    (var-set next-id (+ id u1))
    (ok id)
  )
)

;; VULNERABLE: has auth check but no supply cap
(define-public (admin-mint (recipient principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_NOT_AUTHORIZED)
    (let ((id (var-get next-id)))
      (try! (nft-mint? cool-nft id recipient))
      (var-set next-id (+ id u1))
      (ok id)
    )
  )
)
(define-data-var contract-owner principal tx-sender)

;; SAFE: has MAX-SUPPLY cap check
(define-public (mint-capped)
  (let ((id (var-get next-id)))
    (asserts! (<= id MAX-SUPPLY) ERR_SOLD_OUT)
    (try! (nft-mint? cool-nft id tx-sender))
    (var-set next-id (+ id u1))
    (ok id)
  )
)

;; SAFE: has per-address mint-count limit
(define-public (mint-limited)
  (let (
    (id (var-get next-id))
    (caller-minted (default-to u0 (map-get? mint-count tx-sender)))
  )
    (asserts! (< caller-minted u5) (err u102))
    (try! (nft-mint? cool-nft id tx-sender))
    (map-set mint-count tx-sender (+ caller-minted u1))
    (var-set next-id (+ id u1))
    (ok id)
  )
)
