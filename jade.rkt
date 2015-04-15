#lang racket

(require parsack)

(define text
  (>>= (many1Until $anyChar
                   (lookAhead (<or> (string "#[")
                                    (string "#{")
                                    (string "!{")
                                    $eol)))
       (λ (chars)
         (return (list->string chars)))))

; XXX this is quite incomplete
(define escapedInterpolation
  (between (string "#{")
           (char #\})
           (many $anyChar)))

; XXX this also is quite incomplete
(define unescapedInterpolation
  (between (string "!{")
           (char #\})
           (many $anyChar)))

(define tagInterpolation
  (between (string "#[")
           (char #\])
           (λ (state)  ; element isn't defined yet so wrap in lambda
             (element state))))

(define textLine
  (many1Until (<or> (try escapedInterpolation) ; avoid confusion with tagInterpolation
                    unescapedInterpolation
                    tagInterpolation
                    text)
              $eol))

(define pipedText
  (>> (string "| ")
      textLine))

(define tag
  (>>= (many1 $alphaNum)
       (λ (chars)
         (return (string->symbol (list->string chars))))))

(define attribute
  (parser-seq (>>= (many1 $alphaNum)
                   (λ (chars)
                     (return (string->symbol (list->string chars)))))
              (try (>> (char #\=)
                       (between (char #\")
                                (char #\")
                                (>>= (many1Until $anyChar
                                                 (lookAhead (char #\")))
                                     (λ (chars)
                                       (return (list->string chars)))))))))

(define attributes
  (between (char #\()
           (char #\))
           (sepBy attribute
                  (many1 (<or> $space
                               (char #\,))))))

(define idLiteral
  (>>= (>> (char #\#)
           (many1 $alphaNum))
       (λ (chars)
         (return (list 'id (list->string chars))))))

(define classLiteral
  (>>= (>> (char #\.)
           (many1 $alphaNum))
       (λ (chars)
         (return (list 'class (list->string chars))))))

(define (class-compact attrs)
  (list 'class
        (string-join (map cadr attrs)
                     " ")))

(define literal
  (<or> (try (parser-compose (c1 <- (many classLiteral))
                             (id <- idLiteral)
                             (c2 <- (many classLiteral))
                             (return (list id (class-compact (append c1 c2))))))
        (>>= (many classLiteral)
             (λ (attrs)
               (return (list (class-compact attrs)))))))

(define divLiteral
  (>>= literal
       (λ (attributes)
         (return (list 'div attributes)))))

(define (subseqs seq)
;  (let loop ([seq seq] [x 0])
;    (if (null? seq) (if (>= x 1) '(()) '())
;        (append (for/list ([seq2 (loop (cdr seq) (if (even? x) (add1 x) x))])
;                  (cons (car seq) seq2))
;                (loop (cdr seq) (if (odd? x) (add1 x) x))))))
  (foldr (λ (next acc)
           (append (map (λ (item)
                          (cons next (list item)))
                        acc)
                   (cons (list next)
                         acc)))
         '()
         seq))

(subseqs '(1 2 3 4))

;(define parser-subseq
;  (λ parsers
;    (try (<or> parser-seq

(define element
  (parser-compose (tag <- tag)
                  (etc <- (try (<or> (parser-seq attributes
                                                 (~ $space)
                                                 textLine)
                                     (>> $space
                                         textLine)
                                     (return '()))))
                  (return (cons tag etc))))

(parse textLine "this is text, #[bar], and more text.\n")
;(parse tagInterpolation "#[baz]")
;(parse attribute "baz=\"bak\"")
;(parse attributes "(baz=\"bak\", foo=\"bar\")")
(parse divLiteral ".foo#gomp.bar")
(parse divLiteral ".foo.bar")
(parse divLiteral "#gomp.bar")
(parse divLiteral ".foo#gomp")
(parse element "p(baz=\"bak\") abc #[foo] def #[bar] ghi\n")
(parse element "p(baz=\"bak\", nab=\"ban\") abc #[foo] def #[bar] ghi\n")
