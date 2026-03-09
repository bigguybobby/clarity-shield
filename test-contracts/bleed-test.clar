;; Bleed-across test: exercises the look-ahead boundary bug
;; The mint-public function is UNPROTECTED (no auth check inside its body).
;; But the NEXT function (admin-only) has asserts!/is-owner within 15 lines,
;; which the old naive look-ahead could pick up as a false negative.

(define-fungible-token bleed-token)
(define-data-var contract-owner principal tx-sender)

(define-private (is-owner)
  (is-eq tx-sender (var-get contract-owner)))

;; VULN: No authorization — anyone can mint. Body is only 2 lines.
(define-public (mint-public (amount uint) (recipient principal))
  (ft-mint? bleed-token amount recipient))

;; SAFE: Has proper auth
(define-public (admin-transfer (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) (err u403))
    (ft-transfer? bleed-token amount tx-sender recipient)))

;; VULN: No authorization — anyone can burn
(define-public (burn-public (amount uint))
  (ft-burn? bleed-token amount tx-sender))

;; SAFE: Has proper auth
(define-public (admin-burn (amount uint))
  (begin
    (asserts! (is-owner) (err u403))
    (ft-burn? bleed-token amount tx-sender)))
