#lang racket

(require parsack)

;; convenience procs
(define (maybe p [else null])
  (<or> (try p)
        (return else)))

(define (returnString [transform identity])
  (compose return transform list->string))

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

(define tagInterpolation ; XXX prevent element from eating the "]"
  (between (string "#[")
           (char #\])
           (λ (state)  ; element isn't defined yet so wrap in λ
             (element state))))

(define textLine
  (many1Until (<or> (try escapedInterpolation)
                    unescapedInterpolation
                    tagInterpolation
                    text)
              (lookAhead $eol)))

(define pipedText
  (>> $spaces
      (>> (string "| ")
          (>>= textLine
               (compose return first)))))

;; node parsers
(define tagName
  (maybe (>>= (many1 $alphaNum)
              (returnString string->symbol))
         'div))

(define attribute
  (parser-compose
    (attr <- (>>= (many1 $alphaNum)
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
                               (char #\,))))))

(define andAttributes
  (between (string "&attributes(")
           (char #\))
           rightSide)) ; XXX should iter through the dict
  
(define idLiteral
  (>>= (>> (char #\#)
           (many1 $alphaNum))
       (returnString (curry list 'id))))

(define classLiteral
  (>> (try (lookAhead (>> (char #\.)
                          $alphaNum)))
      (>>= (>> (char #\.)
               (many1 $alphaNum))
           (returnString (curry list 'class)))))

(define (leaveNull item transform)
  (if (null? item)
      item
      (transform item)))

(define tag
  (parser-compose
    (tn <- tagName)
    (c1 <- (many classLiteral))
    (id <- (maybe idLiteral))
    (c2 <- (many classLiteral))
    (a1 <- (maybe attributes))
    (a2 <- (maybe andAttributes))
    (return
      (let*-values ([(attrs) (append a1 a2)]
                    [(clattrs rest) (partition (compose (curry equal? 'class)
                                                        first)
                                               attrs)]
                    [(classes) (map second (append c1 c2 clattrs))])
        (list tn
              (append (leaveNull id
                                 list)
                      (leaveNull classes
                                 (compose list
                                          (curry list 'class)
                                          string-join))
                      rest))))))

(define (indentAtLeast spaces p)
  (>> (try (lookAhead (>> $eol
                          (>> (string (list->string spaces))
                              (many1 $space)))))
      (>> $eol
          p)))

(define element
  (parser-compose
    (indent <- (many (char #\space)))
    (tagAtt <- tag)
    (chldrn <- (<or> (>> (char #\.)
                         (many (indentAtLeast indent
                                              (>> $spaces
                                                  textLine))))
                     (>>= (parser-seq
                            (maybe (>> (char #\space)
                                       textLine))
                            (many (indentAtLeast indent
                                                 (<or> (try pipedText)
                                                       element))))
                          (compose return (curry apply append)))))
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
;(parse textLine "abc #[foo] def #[bar.gee] ghi\n")
(parse element ".po#goo.kob(baz=\"bak\",\n nab=\"ban\" class=\"extra\") abc #[foo] def #[bar.gee] ghi\n")
(parse element "p This is text.\n  | This is more.\n  span#here More\n  | text.\n")
(parse element "p.\n  This is more.\n  Now #[span#here more] text.\n")
;(parse textBlock "  This is text.\n")