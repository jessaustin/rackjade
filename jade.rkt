#lang racket

(require parsack)

;; convenience procs
(define (maybe p [else null])
  (<or> (try p)
        (return else)))

(define (returnString [wrap identity])
  (λ (chars)
    (return (wrap (list->string chars)))))

; XXX this is quite incomplete
; it should include code exec
(define rightSide
  (between (char #\")
           (char #\")
           (>>= (many (noneOf "\""))
                (returnString))))

;; text parsers
(define text
  (>>= (many1Until $anyChar
                   (lookAhead (<or> (string "#[")
                                    (string "#{")
                                    (string "!{")
                                    $eol)))
       (returnString)))

(define escapedInterpolation
  (between (string "#{")
           (char #\})
           rightSide)) ; XXX escape this!

(define unescapedInterpolation
  (between (string "!{")
           (char #\})
           rightSide))

(define tagInterpolation
  (between (string "#[")
           (char #\])
           (λ (state)  ; element isn't defined yet so wrap in λ
             (element state))))

(define textLine
  (many1Until (<or> (try escapedInterpolation) ; back out for tagInterpolation
                    unescapedInterpolation
                    tagInterpolation
                    text)
              $eol))

(define pipedText
  (>> $spaces
      (>> (string "| ")
          textLine)))

(define textBlock
  (parser-compose (indent <- (>>= (lookAhead (many $space))
                                  (returnString)))
                  (lines  <- (>>= (many (>> (string indent)
                                            textLine))
                                  (λ (lines)
                                    (return (map car
                                                 lines)))))
                  (return (string-join lines))))

;; node parsers
(define tagName
  (>>= (many1 $alphaNum)
       (returnString string->symbol)))

(define attribute
  (parser-compose (attr <- (>>= (many1 $alphaNum)
                                (returnString string->symbol)))
                  (valu <- (maybe (>> (char #\=)
                                      rightSide)
                                  (symbol->string attr)))
                  (return (list attr
                                valu))))

(define attributes
  (between (char #\()
           (char #\))
           (sepBy1 attribute
                   (many (<or> $space
                               (char #\,)
                               $eol)))))

(define idLiteral
  (>>= (>> (char #\#)
           (many1 $alphaNum))
       (returnString (λ (id)
                       (list 'id
                             id)))))

(define classLiteral
  (>>= (>> (char #\.)
           (many1 $alphaNum))
       (returnString (λ (class)
                       (list 'class
                             class)))))

(define literals
  (>>= (parser-seq (many classLiteral)
                   (>>= (maybe idLiteral)
                        (λ (id)
                          (return (if (null? id)
                                      id
                                      (list id)))))
                   (many classLiteral))
       (λ (literals)
         (return (apply append
                        literals)))))

(define divLiteral
  (>>= (parser-seq literals
                   attributes)
       (λ (attributes)
         (return (list 'div
                       (apply append
                              attributes))))))

(define tag
  (>>= (<or> divLiteral
             (parser-compose (t  <- tagName)
                             (a1 <- (maybe literals))
                             (a2 <- (maybe attributes))
                             (return (list t
                                           (append a1
                                                   a2)))))
       ; more complicated than we'd like, since list-no-order can't use
       ; multiple ...
       (match-lambda [(list tag attrs)
                      (let*-values ([(class rest)
                                     (partition (λ (item)
                                                  (equal? (car item)
                                                          'class))
                                                attrs)]
                                    [(classes) (map second class)])
                        (return (list tag
                                      (append rest
                                              (if (null? classes)
                                                  null
                                                  (list (list 'class
                                                              (string-join classes))))))))])))

(define element
  (parser-compose (indent <- (>>= (many $space)
                                  (returnString)))
                  (tagAtt <- tag)
                  (chldrn <- (maybe (<or> (parser-seq (maybe (>> $space
                                                                 textLine))
                                                      (~ $eol)
                                                      (~ (lookAhead (string indent)))
                                                      (many (<or> pipedText
                                                                  element)))
                                          (parser-seq (~ (char #\.))
                                                      (~ $eol)
                                                      (~ (lookAhead (string indent)))
                                                      textBlock))))
                  (return (append tagAtt
                                  chldrn))))

;(parse textLine "this is text, #[bar], and more text.\n")
;(parse tagInterpolation "#[baz]")
;(parse attribute "baz=\"bak\"")
;(parse attribute "baz")
;(parse attributes "(baz)")
;(parse attributes "(baz=\"bak\")")
;(parse attributes "(baz=\"bak\", foo=\"bar\"  gee)")
;(parse divLiteral ".foo#gomp.bar")
;(parse tag ".foo.gomp.bar(zap=\"ban\", goff=\"goo\" spoo)")
;(parse tag ".foo#gomp.bar(zap=\"ban\" goff=\"goo\", spoo)")
;(parse tag "p.foo#gomp.bar(zap=\"ban\", goff=\"goo\" spoo)")
;(parse tag "foo")
;(parse divLiteral ".foo.bar")
;(parse divLiteral "#gomp.bar")
;(parse divLiteral ".foo#gomp")
;element
;(parse element "p")
;(parse element "p(baz=\"bak\" foo=\"bar\") abc def ghi\n")
;(parse element ".bax#goo.bar abc def ghi\n")
;(parse element "p(baz=\"bak\") abc #[foo] def #[bar] ghi\n")
;(parse element ".po#goo.kob(baz=\"bak\", nab=\"ban\") abc #[foo] def #[bar.gee] ghi\n")
(parse element "p.\n  This is text.\n  This is more.\n")
(parse textBlock "  This is text.\n")