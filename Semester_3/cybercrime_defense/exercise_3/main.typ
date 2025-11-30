#import "preamble.typ": *

#set page(
    paper: "a4", 
    margin: 2cm,
    number-align: center
)
#set document(
    title: "Exercise 3 - TLS/SSL",
    author: "Philip Magnus",
    date: datetime.today(),
)
#set text(lang: "en")


//Include chapters:
#include "titlepage.typ"

#set page(
    footer: context [
        #set align(center)
        #counter(page).display("-1-")
    ]
)

#outline()

#pagebreak()

#include "chapters/chapter1.typ"
#include "chapters/chapter2.typ"