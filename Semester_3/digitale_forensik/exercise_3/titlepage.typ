#let my-date(..args) = {
  let date = if args.pos().len() == 0 {
    datetime.today()
  } else {
    args.pos().first()
  }
  let day = date.day()
  let suffix = if day in (11, 12, 13) { "th" } else {
    ("st", "nd", "rd").at(calc.rem(day - 1, 10), default: "th")
  }
  date.display("[day padding:none]" + suffix + " of [month repr:long] [year]")
}

#box(image("figures/Hochschule_Campus_Wien_logo.pdf", width: 4.5cm))

#v(7.5cm)

#align(center, block[

  #set align(center)
  #text(1.1em)[
    #strong[Assignment 3]
  ]   

  Digital Forensics

  #text(2.5em, weight: "bold")[Memory Forensics]

  #strong[Author:] \
  Philip Magnus \

  #strong[Student identification number:] \
  c2410537022 \

  #strong[Date:] \
  #my-date()
])

#pagebreak()
