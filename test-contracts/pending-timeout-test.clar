;; Test contract for detector #84: Missing Timeout for Pending Operations

;; --- Maps ---
(define-map pending-orders { id: uint } { seller: principal, amount: uint, buyer: (optional principal) })
(define-map escrow-deposits { deposit-id: uint } { depositor: principal, amount: uint, recipient: principal })
(define-map pending-proposals { proposal-id: uint } { proposer: principal, description: (string-ascii 100), votes: uint })
(define-map safe-pending-orders { id: uint } { seller: principal, amount: uint, deadline: uint })
(define-map safe-escrow { id: uint } { depositor: principal, amount: uint, expires-at: uint })
(define-map user-balances { user: principal } { balance: uint })

(define-data-var next-id uint u0)
(define-data-var admin principal tx-sender)

;; VULNERABLE: pending order without timeout
(define-public (create-order (amount uint))
  (let ((order-id (var-get next-id)))
    (map-insert pending-orders { id: order-id }
      { seller: tx-sender, amount: amount, buyer: none })
    (var-set next-id (+ order-id u1))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; VULNERABLE: escrow deposit without expiry
(define-public (create-escrow (amount uint) (recipient principal))
  (let ((deposit-id (var-get next-id)))
    (map-set escrow-deposits { deposit-id: deposit-id }
      { depositor: tx-sender, amount: amount, recipient: recipient })
    (var-set next-id (+ deposit-id u1))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; VULNERABLE: proposal without deadline
(define-public (submit-proposal (description (string-ascii 100)))
  (let ((prop-id (var-get next-id)))
    (map-insert pending-proposals { proposal-id: prop-id }
      { proposer: tx-sender, description: description, votes: u0 })
    (var-set next-id (+ prop-id u1))
    (ok prop-id)
  )
)

;; SAFE: pending order WITH deadline
(define-public (create-safe-order (amount uint))
  (let ((order-id (var-get next-id)))
    (map-insert safe-pending-orders { id: order-id }
      { seller: tx-sender, amount: amount, deadline: (+ block-height u1440) })
    (var-set next-id (+ order-id u1))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; SAFE: escrow WITH expires-at
(define-public (create-safe-escrow (amount uint) (recipient principal))
  (let ((deposit-id (var-get next-id)))
    (map-set safe-escrow { id: deposit-id }
      { depositor: tx-sender, amount: amount, expires-at: (+ block-height u720) })
    (var-set next-id (+ deposit-id u1))
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)

;; SAFE: not a pending/escrow map (regular user balance)
(define-public (deposit (amount uint))
  (begin
    (map-set user-balances { user: tx-sender } { balance: amount })
    (stx-transfer? amount tx-sender (as-contract tx-sender))
  )
)
