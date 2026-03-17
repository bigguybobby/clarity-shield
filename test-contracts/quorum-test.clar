;; Test contract for #89 Missing Quorum Validation detector

;; ---- Governance maps and variables ----
(define-map proposals { id: uint } { title: (string-ascii 50), votes-for: uint, votes-against: uint, executed: bool })
(define-map vote-records { proposal-id: uint, voter: principal } { vote: bool })
(define-data-var proposal-count uint u0)
(define-data-var treasury principal tx-sender)

;; ---- VULNERABLE: Execute proposal without quorum check ----
(define-public (execute-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals { id: proposal-id }) (err u404)))
    (votes-for (get votes-for proposal))
    (votes-against (get votes-against proposal))
  )
    ;; Only checks majority, not quorum!
    (asserts! (> votes-for votes-against) (err u401))
    (asserts! (not (get executed proposal)) (err u402))
    (map-set proposals { id: proposal-id } (merge proposal { executed: true }))
    (stx-transfer? u1000000 (as-contract tx-sender) (var-get treasury))
  )
)

;; ---- VULNERABLE: Finalize vote without participation threshold ----
(define-public (finalize (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals { id: proposal-id }) (err u404)))
    (votes-for (get votes-for proposal))
  )
    (asserts! (> votes-for u0) (err u403))
    (map-set proposals { id: proposal-id } (merge proposal { executed: true }))
    (stx-transfer? u500000 (as-contract tx-sender) tx-sender)
  )
)

;; ---- SAFE: Execute with quorum threshold ----
(define-constant QUORUM-THRESHOLD u100)
(define-public (execute-with-quorum (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals { id: proposal-id }) (err u404)))
    (votes-for (get votes-for proposal))
    (votes-against (get votes-against proposal))
    (total-votes (+ votes-for votes-against))
  )
    (asserts! (>= total-votes QUORUM-THRESHOLD) (err u405))
    (asserts! (> votes-for votes-against) (err u401))
    (map-set proposals { id: proposal-id } (merge proposal { executed: true }))
    (stx-transfer? u1000000 (as-contract tx-sender) (var-get treasury))
  )
)

;; ---- SAFE: Execute with min-votes requirement ----
(define-constant MIN-VOTES u50)
(define-public (conclude-vote (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals { id: proposal-id }) (err u404)))
    (votes-for (get votes-for proposal))
    (votes-against (get votes-against proposal))
  )
    (asserts! (>= votes-for MIN-VOTES) (err u406))
    (asserts! (> votes-for votes-against) (err u401))
    (map-set proposals { id: proposal-id } (merge proposal { executed: true }))
    (var-set treasury tx-sender)
    (ok true)
  )
)

;; ---- SAFE: Execute with participation-threshold ----
(define-data-var participation-threshold uint u200)
(define-public (resolve-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals { id: proposal-id }) (err u404)))
    (votes-for (get votes-for proposal))
    (votes-against (get votes-against proposal))
    (total (+ votes-for votes-against))
  )
    (asserts! (>= total (var-get participation-threshold)) (err u407))
    (asserts! (> votes-for votes-against) (err u401))
    (map-set proposals { id: proposal-id } (merge proposal { executed: true }))
    (stx-transfer? u200000 (as-contract tx-sender) tx-sender)
  )
)

;; ---- SAFE: Non-execution function (just votes, no state change concern) ----
(define-public (cast-vote (proposal-id uint) (vote-for bool))
  (begin
    (map-set vote-records { proposal-id: proposal-id, voter: tx-sender } { vote: vote-for })
    (ok true)
  )
)

;; ---- NOT A GOVERNANCE CONTRACT (no proposal/voting patterns) ----
;; This function should NOT be flagged even though it's named "execute"
;; because the contract context lacks governance patterns (handled by the
;; initial contract-level governance check)
