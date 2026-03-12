;; Test contract for Insecure Randomness detector (#76)

;; VULNERABLE: Uses block-height + mod for lottery selection
(define-public (pick-winner (entries (list 100 principal)))
  (let (
    (random-index (mod block-height (len entries)))
    (winner (unwrap! (element-at entries random-index) (err u1)))
  )
    (try! (stx-transfer? u1000000 tx-sender winner))
    (ok winner)
  )
)

;; VULNERABLE: Uses burn-block-height + hash for NFT trait selection
(define-public (mint-random-nft)
  (let (
    (seed (sha256 burn-block-height))
    (trait-id (mod (buff-to-uint-be seed) u10))
  )
    (print { event: "nft-minted", trait: trait-id })
    (ok trait-id)
  )
)

;; SAFE: Uses VRF for randomness (acknowledged external source)
(define-public (pick-winner-vrf (entries (list 100 principal)) (vrf-seed (buff 32)))
  (let (
    (random-index (mod (buff-to-uint-be vrf-seed) (len entries)))
    (winner (unwrap! (element-at entries random-index) (err u1)))
  )
    (try! (stx-transfer? u1000000 tx-sender winner))
    (ok winner)
  )
)

;; SAFE: Uses block-height for time-based logic (not randomness)
(define-public (check-unlock)
  (begin
    (asserts! (>= block-height u100000) (err u1))
    (ok true)
  )
)

;; SAFE: Pure commit-reveal scheme without on-chain randomness
(define-public (reveal-commit-reveal (commit-hash (buff 32)) (secret (buff 32)))
  (let (
    (computed-hash (sha256 secret))
    (random-val (mod (buff-to-uint-be computed-hash) u100))
  )
    (asserts! (is-eq computed-hash commit-hash) (err u1))
    (ok random-val)
  )
)
