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
#set text(lang: "en", font: "Arial")

#let clean_numbering(..schemes) = {
  (..nums) => {
    let (section, ..subsections) = nums.pos()
    let (section_scheme, ..subschemes) = schemes.pos()

    if subsections.len() == 0 {
      numbering(section_scheme, section)
    } else if subschemes.len() == 0 {
      numbering(section_scheme, ..nums.pos())
    }
    else {
      clean_numbering(..subschemes)(..subsections)
    }
  }
}

#set heading(numbering: "1.")

//Include titlepage
#include "titlepage.typ"

#set page(
    footer: context [
        #set align(center)
        #counter(page).display("-1-")
    ]
)


//Include table of contents
#outline()
#pagebreak()

//Include chapters
#include "chapters/chapter1.typ"
#include "chapters/chapter2.typ"