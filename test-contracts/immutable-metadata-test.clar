;; Test contract for detector #83 - Immutable Token Metadata (SAFE)

;; Immutable metadata using constants
(define-constant TOKEN-NAME "Safe Token")
(define-constant TOKEN-SYMBOL "SAFE")
(define-constant TOKEN-DECIMALS u8)
(define-constant TOKEN-URI (some u"https://example.com/safe-metadata.json"))

;; Safe: get-name returns constant
(define-read-only (get-name)
    (ok TOKEN-NAME)
)

;; Safe: get-symbol returns constant
(define-read-only (get-symbol)
    (ok TOKEN-SYMBOL)
)

;; Safe: get-decimals returns constant
(define-read-only (get-decimals)
    (ok TOKEN-DECIMALS)
)

;; Safe: get-token-uri returns constant
(define-read-only (get-token-uri)
    (ok TOKEN-URI)
)
