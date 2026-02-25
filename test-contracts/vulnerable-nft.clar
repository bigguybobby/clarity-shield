;; Vulnerable NFT Marketplace
;; Contains access control and validation issues

(define-non-fungible-token stacks-nft uint)

(define-map listings uint {
  seller: principal,
  price: uint,
  active: bool
})

(define-data-var next-token-id uint u1)
(define-data-var marketplace-fee uint u250) ;; 2.5%

;; VULN: Public mint without authorization
(define-public (mint (uri (string-utf8 256)))
  (let ((token-id (var-get next-token-id)))
    ;; VULN: Anyone can mint NFTs
    (try! (nft-mint? stacks-nft token-id tx-sender))
    (var-set next-token-id (+ token-id u1))
    (ok token-id)))

;; VULN: Missing validation on listing creation
(define-public (list-nft (token-id uint) (price uint))
  (begin
    ;; VULN: No check if caller owns the NFT
    ;; VULN: No check if NFT is already listed
    (map-set listings token-id {
      seller: tx-sender,
      price: price,
      active: true
    })
    (ok true)))

;; VULN: Race condition in purchase
(define-public (purchase-nft (token-id uint))
  (let (
    ;; VULN: map-get? without default
    (listing (unwrap! (map-get? listings token-id) (err u404)))
  )
    ;; VULN: Check happens AFTER unwrap
    (asserts! (get active listing) (err u405))
    
    ;; VULN: Price calculation without overflow check
    (let (
      (price (get price listing))
      (fee (* price (var-get marketplace-fee)))
      (seller-amount (- price (/ fee u10000)))
    )
      ;; Transfer payment
      (try! (stx-transfer? seller-amount tx-sender (get seller listing)))
      
      ;; VULN: NFT transfer without checking success
      (nft-transfer? stacks-nft token-id (get seller listing) tx-sender)
      
      ;; Delist
      (map-set listings token-id (merge listing {active: false}))
      (ok true))))

;; VULN: contract-caller in admin function
(define-public (set-marketplace-fee (new-fee uint))
  (begin
    ;; VULN: Using contract-caller for auth
    (asserts! (is-eq contract-caller 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7) (err u403))
    (ok (var-set marketplace-fee new-fee))))

;; VULN: No bounds checking on fee
(define-public (update-fee (fee uint))
  (begin
    ;; VULN: Fee could be set to > 100% (u10000 = 100%)
    (ok (var-set marketplace-fee fee))))

(define-read-only (get-listing (token-id uint))
  (map-get? listings token-id))
