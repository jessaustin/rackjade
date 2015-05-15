#lang racket

(require parsack)
(require xml)      ; for make-comment: is there a better option for this?

;; convenience procs

; this one is useful enough to be included in parsack; "p" is a parser
(define (maybe p [else null])
  (<any> (try p)
         (return else)))

; parsack produces lots of lists of chars
(define (returnString [transform identity])
  (compose return
           transform
           list->string))

; if consecutive items in lists are strings, combine them into one string
(define collapseStrings
  (compose (curry foldr
                  (match-lambda**
                    [("" z) z]
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

(define blockLevels
  (list "b" "big" "i" "small" "tt" "abbr" "acronym" "cite" "code" "dfn" "em"
        "kbd" "strong" "samp" "var" "a" "bdo" "br" "img" "map" "object" "q"
        "script" "span" "sub" "sup" "button" "input" "label" "select"
        "textarea"))

; XXX this is quite incomplete
; it should include code exec
(define rightSide
  (between (char #\")
           (char #\")
           (>>= (many (noneOf "\""))
                (returnString))))

;; text parsers
(define text
  (>>= (many1 (<!> (>>= (getState 'insideBrackets)
                        (λ (insideBrackets)
                          (if insideBrackets
                              (<any> (char #\])
                                     (string "#[")
                                     (string "#{")
                                     (string "!{"))
                              (>>= (getState 'insideBraces)
                                   (λ (insideBraces)
                                     (if insideBraces
                                         (char #\})
                                         (<any> (string "#[")
                                                (string "#{")
                                                (string "!{")
                                                $eol
                                                $eof)))))))))
       (returnString string-trim))) ; XXX might want to trim in collapseStrings so we can save one space next to e.g. a span

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
  (many1 (<or> (try escapedInterpolation)
               unEscapedInterpolation
               tagInterpolation
               text)))

(define pipeText
  (between (char #\|)
           (<any> $eol
                  $eof)
           textLine))

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
           (sepBy1 _attribute
                   (many (oneOf " ,")))))

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
  (<any> (>> (string ": ")
             inLineNode)
         (>> (char #\space)
             textLine)))

(define children
  (<any> (parser-one (string ": ")  ; inline element is only child: any
                     (~> _element)) ; following lines are children of text
         (>>= (<any> (>> (char #\.) ; block is only child
                         (>> $eol
                             (many (parser-one indentMore
                                               (~> textLine)
                                               (<any> $eol
                                                      $eof)))))
                     (parser-seq (maybe textLine)
                                 (~ (<any> $eol
                                           $eof))
                                 (>>= (many (>> indentMore  ; many children
                                                (>>= (many1 (char #\space))
                                                     (λ (spaces)
                                                       (withState (['indented spaces])
                                                                  _element)))))
                                      (compose return
                                               append*))))
              (compose return
                       collapseStrings))))

(define node
  (>>= (parser-seq tag
                   children)
       (compose return
                list
                append*)))

(define unBufferedComment
  (>> (string "//-")
      (>> children
          (return null))))

(define _comment
  (>> (string "//")
      (>>= (parser-seq (>>= (many (<!> $eol))
                            (compose return
                                     list->string))
                       (>> $eol
                           (>>= (many (parser-one indentMore
                                                  (many (char #\space))
                                                  (~> (many (<!> $eol)))
                                                  $eol))
                                (compose return
                                         string-join
                                         (curry map
                                                list->string)))))
           (compose return
                    list
                    make-comment
                    string-join))))

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

(define _element
  (<any> pipeText
         (try unBufferedComment)
         _comment
         node))

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
      p #[strong What] about content?
        | #[i Here] is some content. Content
        | is great.
        | So great that
        | I just can't help myself.
        span This is a span
        | and this is text after the span.
      p.
        What
        about #[i this] content?
      p.
        #[i Very #[strong interesting]] content, however, is 
        often difficult to find.
        ...or even to imagine.
      // now...
        how about some comments?
      // here's
         another
         comment, but there's a
         #[i problem] here
      p
        | One
        span lonely span
        | and another,
        span not-so-lonely, span
      p #[strong This] is a short paragraph.
      #end")