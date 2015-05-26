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
                     (cons (string-join `(,a ,b)) z)]
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

(define inLineLevels
  '(a abbr acronym b bdo big br button cite code dfn em i img input kbd label
    map object q samp script select small span strong sub sup textarea tt var))

(define rightSide
  (>>= (many1 (<!> (<any> (char #\}) ; maybe this should only be inBraces?
                          $eol
                          $eof)))
       (λ (code)
         (current-namespace (make-base-namespace))
         (let ([x (eval (list->string code))])
           (print x)
           (return x)))))

(define attrRightSide
  (>>= (<any> (between (char #\()
                       (char #\))
                       (many (<!> (char #\)))))
              (many1 (<!> (<any> (char #\space)
                                       $eol
                                       $eof))))
       (λ (code)
         (return (eval (list->string code)
                       )))))

;; text parsing
(define escapedInterpolation
  (between (string "#{")
           (char #\})
           (withState (['inBraces #t])
                      rightSide))) ; XXX escape this!

(define unEscapedInterpolation
  (between (string "!{")
           (char #\})
           (withState (['inBraces #t])
                      rightSide)))

(define tagInterpolation
  (between (string "#[")
           (char #\])
           (withState (['inBrackets #t])
                      inLineNode)))

(define text
  (>>= (many1 (<!> (>>= (getState 'inBraces)
                        (λ (inBraces)
                          (if inBraces
                              (char #\})
                              (>>= (getState 'inBrackets)
                                   (λ (inBrackets)
                                     (apply <any>
                                            (append `(,(string "#[")
                                                      ,(string "#{")
                                                      ,(string "!{"))
                                                    (if inBrackets
                                                        `(,(char #\]))
                                                        `(,$eol
                                                          ,$eof)))))))))))
       (returnString)))

(define textLine
  (many1 (<or> (try escapedInterpolation)
               unEscapedInterpolation
               tagInterpolation
               text)))

(define pipeText
  (between (>> (char #\|)
               (maybe (char #\space)))
           (<any> $eol
                  $eof)
           textLine))

(define hyphenLine
  (>> (between (char #\-)
               (<any> $eol
                      $eof)
               rightSide)
      (return null)))

;; node parsers
(define tagName
  (maybe (>>= (many1 $alphaNum)
              (returnString string->symbol))
         'div))  ; clever!

; attribute names can contain funny characters
(define _attribute
  (parser-compose (attr <- (>>= (many1 (<!> (<any> $space
                                                   (satisfy char-iso-control?)
                                                   (char #\")
                                                   (char #\')
                                                   (char #\/)
                                                   (char #\>)
                                                   (char #\=))))
                                (returnString string->symbol)))
                  (value <- (maybe (>> (char #\=)
                                       attrRightSide) ; XXX this might need more
                                   (symbol->string attr)))
                  (return `(,attr ,value))))

(define attributes
  (between (char #\()
           (char #\))
           (sepBy1 _attribute
                   (many1 (oneOf " ,")))))

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
        `(,tn ,(append (if (null? id)
                           id
                           `(,id))
                       (if (null? classes)
                           classes
                           `(('class ,(string-join classes))))
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
                                               (many (char #\space))
                                               (~> textLine)
                                               (<any> $eol
                                                      $eof)))))
                     (parser-seq (maybe (>> (char #\space)
                                            textLine))
                                 (~ (<any> $eol
                                           $eof))
                                 (>>= (many (>> indentMore  ; many children
                                                (>>= (many1 (char #\space))
                                                     (λ (spaces)
                                                       (withState
                                                         (['indented spaces])
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
         hyphenLine
         (try unBufferedComment)
         _comment
         node))

(parse _element
"html
  - (define x \"yolo\")
  body
    p#first.
      This is an introductory paragraph.
    #nav.nav
      // ol
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
        //span(weirdA$$-attr=\"yo\") lonely span
        | and another,
        span not-so-lonely, span
      p #[strong This] is a short paragraph.
      #end")