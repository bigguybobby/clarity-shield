;; Test contract for Signature Replay Vulnerability detector (#91)

;; --- VULNERABLE FUNCTIONS ---

;; #1: Uses secp256k1-recover? without nonce tracking
(define-public (execute-signed-action (message (buff 256)) (signature (buff 65)))
  (let ((signer (try! (secp256k1-recover? (sha256 message) signature))))
    (stx-transfer? u1000 tx-sender (unwrap-panic (principal-of? signer)))
  )
)

;; #2: Uses secp256k1-verify without nonce tracking
(define-public (verify-and-transfer (hash (buff 32)) (signature (buff 65)) (pub-key (buff 33)) (amount uint))
  (begin
    (asserts! (secp256k1-verify hash signature pub-key) (err u401))
    (stx-transfer? amount tx-sender tx-sender)
  )
)

;; --- SAFE FUNCTIONS ---

;; #3: Has nonce tracking with map
(define-map user-nonces principal uint)

(define-public (execute-with-nonce (message (buff 256)) (signature (buff 65)) (nonce uint))
  (let ((signer (try! (secp256k1-recover? (sha256 message) signature)))
        (current-nonce (default-to u0 (map-get? user-nonces tx-sender))))
    (asserts! (is-eq nonce current-nonce) (err u100))
    (map-set user-nonces tx-sender (+ current-nonce u1))
    (ok true)
  )
)

;; #4: Has used-signatures tracking
(define-map used-signatures (buff 65) bool)

(define-public (execute-once (message (buff 256)) (signature (buff 65)))
  (let ((signer (try! (secp256k1-recover? (sha256 message) signature))))
    (asserts! (is-none (map-get? used-signatures signature)) (err u200))
    (map-set used-signatures signature true)
    (ok true)
  )
)

;; #5: Has replay guard variable
(define-data-var last-nonce uint u0)

(define-public (guarded-verify (hash (buff 32)) (signature (buff 65)) (pub-key (buff 33)) (sequence uint))
  (begin
    (asserts! (> sequence (var-get last-nonce)) (err u300))
    (asserts! (secp256k1-verify hash signature pub-key) (err u401))
    (var-set last-nonce sequence)
    (ok true)
  )
)

;; #6: Read-only function using signature verification (not vulnerable - can't change state)
(define-read-only (check-signature (hash (buff 32)) (signature (buff 65)) (pub-key (buff 33)))
  (ok (secp256k1-verify hash signature pub-key))
)

;; #7: No signature operations at all
(define-public (simple-transfer (amount uint))
  (stx-transfer? amount tx-sender tx-sender)
)
