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

;; text parsers
(define text
  (>>= (many1Until $anyChar
                   (lookAhead (<or> (try (string "#["))
                                    (try (string "#{"))
                                    (try (string "!{"))
                                    $eol
                                    $eof)))
       (returnString string-trim)))

(define escapedInterpolation
  (between (string "#{")
           (char #\})
           rightSide)) ; XXX escape this!

(define unEscapedInterpolation
  (between (string "!{")
           (char #\})
           rightSide))


(define tagInterpolation
  (between (string "#[")
           (char #\])
           (>>= (many (<!> (char #\])))
;                (returnString (compose parse-result (node null))))))
                (λ (state)
                  (return (parse-result (node null)
                                        (list->string state)))))))

(define textLine
  (>> justSpaces
      (many1Until (<or> (try escapedInterpolation)
                        unEscapedInterpolation
                        tagInterpolation
                        text)
                  (<or> $eol
                        $eof))))

(define pipeText
  (>> justSpaces
      (>> (string "| ")
          (>>= textLine
               (compose return first)))))

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

(define attr
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
           (sepBy1 attr
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

(define (indentAtLeast spaces)
  (try (lookAhead (>> (string (list->string spaces))
                      (many1 $space)))))

(define (children indent)
  (<or> (>> (string ": ")                        ; inline element is only child
            (>>= (_element indent)
                 (compose return
                          list)))
        (>>= (<or> (>> (char #\.)                ; text block is only child
                       (>> $eol
                           (many (>> (indentAtLeast indent)
                                     textLine))))
                   (parser-seq (<or> (>> (char #\space)
                                         textLine)
                                     (>> $eol
                                         (return null))
                                     $eof)
                               (many (>> (indentAtLeast indent)
                                         (_element)))))
             (compose return
                      collapseStrings))))

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


(define (unBufferedComment indent)
  (>> (string "//-")
      (>> (children indent)
          (return null))))

(define (_comment indent)
  (>> (string "//")
      (>>= (parser-cons (<or> textLine
                              (>> $eol
                                  (return null)))
                        (many (>> (indentAtLeast indent)
                                  textLine)))
           (compose return
                    make-comment
                    car
                    collapseStrings))))

(define (node indent)
  (parser-compose
    (tagAtt <- tag)
    (chldrn <- (children indent))
    (return (append tagAtt
                    chldrn))))

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
    (cases <- (many (parser-seq (~ (indentAtLeast indent))
                                (~ (string "when"))
                                (~ (many1 $space))
                                (>>= rightSide
                                     (compose return
                                              (curry equal? var)))
                                children)))
    (default <- (maybe (>> (indentAtLeast indent)
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

; indent is passed in when element is on the same line with its parent and ":"
; otherwise justSpaces figures it out
(define (_element [indent null])
  (parser-compose
    (indent <- (if (pair? indent)
                   (return indent)
                   justSpaces))
    (e <- (<or> pipeText               ; pipeText has no children, so no indent
                (try (unBufferedComment indent))
                (_comment indent)
                (node indent)
                conditional
                case))
    (return e)))

(parse (_element)
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
        span This is a span
        | and this is text after the span.
      p.
        #[i Interesting] content, however, is 
        often difficult to find.
      // This is a
         comment!
         That goes on and on.
      p This is a short paragraph.
      #end")