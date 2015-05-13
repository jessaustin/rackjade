#lang racket

(require parsack)
(require xml)

;; convenience procs

; this one is useful enough to be included in parsack; "p" is a parser
(define (maybe p [else null])
  (<or> (try p)
        (return else)))

; because $spaces includes #\newline, which we never want
(define justSpaces
  (many (char #\space)))

; parsack produces lots of lists of chars
(define (returnString [transform identity])
  (compose return
           transform
           list->string))

; if consecutive items in lists are strings, combine them into one string
(define collapseStrings
  (compose (curry foldr
                  (match-lambda**
                    [((? string? a)
                      (cons (? string? b) z))
                     (cons (string-join (list a b)) z)]
                    [(a z) (cons a z)])
                  null)
           append*))

; This seems excessive, but see
; www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
; This covers rules 1 & 2. Maybe we should also cover rule 3, but probably you
; just shouldn't put user-supplied data into js expressions.
(define escape
  (compose string-append*
           (curry map
                  (λ (chr)
                    (if (or (char<=? #\Ā chr)  ; >= 256
                            (char-alphabetic? chr)
                            (char-numeric? chr))
                        (make-string 1 chr)
                        (string-append "&#x"
                                       (~r (char->integer chr)
                                           #:min-width 2
                                           #:pad-string "0"
                                           #:base 16)))))
           string->list))

; XXX this is quite incomplete
; it should include code exec
(define rightSide
  (between (char #\")
           (char #\")
           (>>= (many (noneOf "\""))
                (returnString))))

;; text parsers  XXX clean up
(define text
  (>>= (getState 'insideBrackets)
       (λ (inside)
         (if inside
             (>>= (many1Until (noneOf "]")
                              (lookAhead (<any> (try (string "#["))
                                                (try (string "#{"))
                                                (try (string "!{"))
                                                (char #\])
                                                $eol
                                                $eof)))
                  (returnString string-trim))
             (>>= (many1Until (<!> $eol)
                              (lookAhead (<any> (try (string "#["))
                                                (try (string "#{"))
                                                (try (string "!{"))
                                                $eol
                                                $eof)))
                  (returnString string-trim))))))

(define escapedInterpolation
  (between (string "#{")
           (char #\})
           (withState (['insideBraces #t])
                      rightSide))) ; XXX escape this!

(define unEscapedInterpolation
  (between (string "!{")
           (char #\})
           (withState (['insideBraces #t])
                      rightSide)))

(define tagInterpolation
  (between (string "#[")
           (char #\])
           (withState (['insideBrackets #t])
                      inLineNode)))

(define textLine
  (many (<or> (try escapedInterpolation)
              unEscapedInterpolation
              tagInterpolation
              text)))

(define pipeText
  (>> (string "| ")
      (>>= textLine
           (λ (txt)
             (>> (<or> $eol
                       $eof)
                 (return (car txt)))))))

;; node parsers
(define tagName
  (maybe (>>= (many1 $alphaNum)
              (returnString string->symbol))
         'div))  ; clever!

; Attributes have a name and a value. Attribute names must consist of one or more characters other than the space characters,
; U+0000 NULL, U+0022 QUOTATION MARK ("), U+0027 APOSTROPHE ('), ">" (U+003E), "/" (U+002F), and "=" (U+003D) characters, the
; control characters, and any characters that are not defined by Unicode. In the HTML syntax, attribute names, even those for
; foreign elements, may be written with any mix of lower- and uppercase letters that are an ASCII case-insensitive match for
; the attribute's name.

(define _attribute
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
           (sepBy1 _attribute
                   (many (<or> (char #\space)
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
  (>> (try (lookAhead (>> (char #\.)   ; ensure we're not starting a text block
                          $alphaNum)))
      (>>= (>> (char #\.)
               (many1 $alphaNum))
           (returnString (curry list 'class)))))

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
                    [(cA etc) (partition (compose (curry equal? 'class)
                                                  first)
                                         attrs)]
                    [(classes) (map second (append c1 c2 cA))])
        (list tn
              (append (if (null? id)
                          id
                          (list id))
                      (if (null? classes)
                          classes
                          (list (list 'class
                                      (string-join classes))))
                      etc))))))

(define buffered rightSide)
(define unEscaped rightSide)

;; handling whitespace
; indent more than parent
(define indentMore
  (>>= (getState 'indented)
       (λ (spaces)
         (if (pair? spaces)
             (try (lookAhead (>> (string (list->string spaces))
                                 (many1 $space))))
             (return null)))))

(define inLineNode
  (>>= (parser-seq tag
                   (maybe inLineChildren))
       (compose return
                append*)))

(define inLineChildren
  (>>= (<any> (>> (string ": ")
                  inLineNode)
              (>> (char #\space)
                  textLine))
       (compose return list)))

(define children
  (<or> (parser-compose (string ": ")      ; inline element is only child:
                        (e <- _element)    ; any following lines are children
                        (return (list e))) ; of inline element
        (>>= (<or> (>> (char #\.)          ; text block is only child
                       (>> $eol
                           (many (parser-one indentMore
                                             (~> textLine)
                                             (<or> $eol
                                                   $eof)))))
                   (parser-seq (maybe textLine)
                               (~ (<or> $eol
                                        $eof))
                               (many (>> indentMore  ; many children
                                         (>>= (many1 (char #\space))
                                              (λ (spaces)
                                                (withState (['indented spaces])
                                                           _element)))))))

             (compose return
                      collapseStrings))))

(define node
  (parser-compose
    (tagAtt <- tag)
    (chldrn <- children)
    (return (append tagAtt
                    chldrn))))

(define unBufferedComment
  (>> (string "//-")
      (>> children
          (return null))))

(define _comment
  (>> (string "//")
      (>>= (parser-cons (maybe textLine)
                        (>> $eol
                            (many (parser-one indentMore
                                              (~> textLine)
                                              $eol))))
           (compose return
                    make-comment
                    car
                    collapseStrings))))


; special: mixin
;          case when default
;          if else if else unless
;          extends block (append prepend)
;          include
;          each (v, i) in (list)
;          while (t/f) 
; //
; -
; =
; !=

(define conditional
  (parser-compose
    (indent <- justSpaces)
    (string "if")
    (many1 $space)
    (cond <- (parser-seq rightSide
                         children))
    (conds <- (many (>> (string "else if")
                        (>> (many1 $space)
                            (parser-seq rightSide
                                        children)))))
    (else <- (maybe (>> (string "else")
                        (>> (many1 $space)
                            (parser-seq rightSide
                                        children)))))
    (return (cadr (assf identity
                        (cons cond
                              (append conds
                                      else)))))))

(define case
  (parser-compose
    (indent <- justSpaces)
    (string "case")
    (many1 $space)
    (var <- rightSide)
    (many1 $space)
    (cases <- (many (parser-seq (~ indentMore)
                                (~ (string "when"))
                                (~ (many1 $space))
                                (>>= rightSide
                                     (compose return
                                              (curry equal? var)))
                                children)))
    (default <- (maybe (>> indentMore
                           (>> (string "default")
                               (>> (many1 $space)
                                   (>>= children
                                        (compose return
                                                 (curry list #t))))))))
    (return (cadr (assf identity
                        (append cases
                                default))))))

;(define each
 ; (parser-compose
  ;  (indent <- justSpaces)
   ; (<or> (string "each")
    ;      (string "for"))
;    (many1 $space)
 ;   (lst <- rightSide)
  ;  (return (map ()
   ;              lst))))

;(define while
 ;   (parser-compose
  ;  (indent <- justSpaces)
   ; (string "while")
    ;(many1 $space)
    ;( <- rightSide)

(define _element
  (<or> pipeText
        (try unBufferedComment)
        _comment
        node
        conditional
        case))

(parse textLine "this is a #[i line] of text")
(parse tagInterpolation "#[i: strong]")
(parse tagInterpolation "#[i #[strong  ]  ]")
(parse tagInterpolation "#[i line]")
(parse textLine "this is a #[i #[strong line]] of text")

(parse _element
"html
  body
    p#first.
      This is an introductory paragraph.
    #nav.nav
      ol
        li: a(href=\"one.html\") One
        li
          a(href=\"two.html\") Two
    #main.content
      p
        | Here is some content. Content
        | is great.
        | So great that
        | I just can't help myself.
        span This is a span
        | and this is text after the span.
      p.
        #[i Very #[strong interesting]] content, however, is 
        often difficult to find.
        ...or even to imagine.
      // This is a
         comment
            That goes on and on.
      p This is a short paragraph.
      #end
")