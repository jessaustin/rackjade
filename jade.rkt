#! /usr/bin/env racket
#lang racket

(require parsack)

(provide parse-jade)

(define (parse-jade)
  '())

(define text
  (>>= (many (<!> (oneOfStrings "#[" "#{" "!{")))
       (λ (x)
         (return (string-append "text: \""
                                (list->string x)
                                "\"")))))

(define tagInterpolation
  (between (string "#[")
           (string "]")
           element))

(define textline
  (manyUntil (<or> text
                   tagInterpolation)
             $eol))

(define pipedText
  (>> (string "| ")
      textline))

(define tag
  (>>= (many1 $alphaNum)
       (λ (x)
         (return (string-append "tag: "
                                (list->string x))))))

(define element
  (parser-compose (tag <- tag)
                  (text <- (try text))
                  (return (list tag text))))

(parse textline "this is text, #[bar], and more text.\n")
;(parse tagInterpolation "#[baz]")
(parse element "p abc #[foo] def #[bar] ghi\n")