;; Test contract for detector #83 - Mutable Token Metadata

;; Mutable metadata (VULNERABLE)
(define-data-var token-name (string-ascii 32) "Fake Token")
(define-data-var token-symbol (string-ascii 10) "FAKE")
(define-data-var token-decimals uint u6)
(define-data-var token-uri (optional (string-utf8 256)) (some u"https://example.com/metadata.json"))

;; Admin who can change metadata
(define-data-var contract-owner principal tx-sender)

;; Vulnerable: get-name returns mutable var
(define-read-only (get-name)
    (ok (var-get token-name))
)

;; Vulnerable: get-symbol returns mutable var
(define-read-only (get-symbol)
    (ok (var-get token-symbol))
)

;; Vulnerable: get-decimals returns mutable var
(define-read-only (get-decimals)
    (ok (var-get token-decimals))
)

;; Vulnerable: get-token-uri returns mutable var
(define-read-only (get-token-uri)
    (ok (var-get token-uri))
)

;; Setter that allows admin to change name (confirms mutability)
(define-public (set-token-name (new-name (string-ascii 32)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
        (var-set token-name new-name)
        (ok true)
    )
)

;; Setter for symbol
(define-public (set-token-symbol (new-symbol (string-ascii 10)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) (err u403))
        (var-set token-symbol new-symbol)
        (ok true)
    )
)
