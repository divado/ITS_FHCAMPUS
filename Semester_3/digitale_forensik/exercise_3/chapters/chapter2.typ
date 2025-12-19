= Assignment - Part 1
#v(0.5cm)

== Setup and Acquisition of RAM Dump
#v(0.5cm)

First I created a RAM dump of my running Ubuntu 24.04 LTS system using `AVML`.

To comply with the exercise I added a unique artifact by opening a `gif` image, with the name `giphy-3348127193.gif` (see @fig-sponge), in the default image viewer application.

#v(0.5cm)


#align(center, block[
  #figure(
    image("../figures/giphy-3348127193.gif", width:60%),
    caption: "Unique artefact - opened gif image in default image viewer."
  )<fig-sponge>
])

#v(0.5cm)

This was not the only process running on the system, I also had a Vivaldi browser window open with multiple tabs.
For this I downloaded the latest pre compiled binary from the official `AVML` GitHub repository and executed the following command with `sudo` privileges to create a memory dump named `ram.dump`:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ sudo ./avml ram.dump
    ```,
    caption: "Creating a RAM dump using AVML."
  )<fig-avml>
])

#v(0.5cm)

This resulted in a $32$GB RAM dump file named `ram.dump` in the current working directory. I also generated the `sha256` checksum of the dump file to ensure integrity during analysis:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ sha256sum ram.dump
      
      992f44d0995022e472f3e23049b27879de01a78218651f894656ce58260391e1  ram.dump
    ```,
    caption: "Sha256 checksum of ram.dump."
  )
])

#v(0.5cm)

== Set up Volatility 3 for Analysis
#v(0.5cm)

For the analysis of the acquired RAM dump I used `Volatility 3`. First I installed `Volatility 3` using `pip`:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ python -m venv .venv && source .venv/bin/activate

    $ pip install git+https://github.com/Abyss-W4tcher/volatility3.git@issue_1761_module_sect_attr_fix
    ```,
    caption: "Installing Volatility 3."
  )
])

#v(0.5cm)

#highlight[Note: Volatility3 needs to be installed from the branch corresponding with PR#1773 due to issue #1883, which prevents analysing of dumps of current `Linux` kernel versions)]

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ chmod -w+r ram.dump
    ```,
    caption: "Make dump read-only."
  )<list-readonly>
])

#v(0.5cm)

As shown in @list-readonly, I made the dump file read-only to prevent accidental modification during analysis. Using the `vol -f ram.dump banners`, see @fig-banners, command I checked for the `Linux` version of the acquired dump, this is necessary to create the correct symbols table for analysis.

#v(0.5cm)


#align(center, block[
  #figure(
    image("../figures/vol-banners.png"),
    caption: "vol -f ram.dump banners output"
  )<fig-banners>
])

#v(0.5cm)

The newest `Linux` kernel version found in the dump is `6.14.0-36-generic`. The other versions are previous kernels that are left over after system updates.

Next I created the correct symbols table which is crucial for the analysis of the dump. First I installed the kernel debug symbols using `apt`, see @list-aptDebugKernelSymbols.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ sudo apt install linux-image-amd64-dbg -y
    ```,
    caption: "Downloading kernel debug symbols."
  )<list-aptDebugKernelSymbols>
])

#v(0.5cm)

Next I downloaded and compiled `dwarf2json` as described in the git repository (#link("https://github.com/volatilityfoundation/dwarf2json", "dwarf2json")). With the command shown in @list-dwarf2json I generated the symbols table for `Volatility 3`.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.14.0-36-generic | xz -c > linux-6.14.json.xz 
    ```,
    caption: "Creating symbols table for Volatility 3 using dwarf2json."
  )<list-dwarf2json>
])

#v(0.5cm)

I then placed the generated `linux-6.14.json.xz` file in the `volatility3/sybols` directory to make it available for `Volatility 3`, see @list-copySymbols.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ cp ~/workspace/dwarf2json/linux-6.14.json.xz .venv/lib/python3.12/site-packages/volatility3/symbols
    ```,
    caption: "Creating symbols table for Volatility 3 using dwarf2json."
  )<list-copySymbols>
])

#v(0.5cm)

== Analysis of RAM Dump
#v(0.5cm)

=== Analysis of Running and Terminated Processes
#v(0.5cm)

With the setup complete I started the analysis of the RAM dump. First I executed the following two commands:

- `vol -f ram.dump linux.pslist`
- `vol -f ram.dump linux.psscan`

First I listed the interesting running processes using the `linux.pslist` plugin, see @fig-pslist. Here I could already identify the opened image viewer process `eog` (Eye of GNOME), as well as the open Vivaldi browser processes `vivaldi-bin`.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/pslist.png", width: 80%),
    caption: "vol -f ram.dump linux.pslist output"
  )<fig-pslist>
])

#v(0.5cm)

Next I used the `linux.psscan` plugin to find terminated processes that are still present in memory, see @fig-psscan. Here I could again identify multiple `eog` and `vivaldi-bin` processes that were terminated or intentionally "unlinked" but still present in memory.

#align(center, block[
  #figure(
    image("../figures/psscan.png", width: 80%),
    caption: "vol -f ram.dump linux.psscan output"
  )<fig-psscan>
])

#v(0.5cm)

All in all the `pslist` plugin found $489$ processes, while the `psscan` plugin found $2775$ processes.

=== Analysis of Open Network Connections
#v(0.5cm)

With the command shown in @list-sockstat I listed all open network connections using the `linux.socket.sockstat` plugin.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f ram.dump linux.sockstat.Sockstat
    ```,
    caption: "Listing open network connections using linux.sockstat.Sockstat plugin."
  )<list-sockstat>
])

#v(0.5cm)

The output of the command is shown in @fig-sockstat. Here I can see all the open sockets in different states, including `LISTEN`, `ESTABLISHED` and `CLOSE_WAIT`.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/netstat1.png", width: 80%),
    caption: "Sockstat output."
  )<fig-sockstat>
])

#v(0.5cm)

To narrow down the results I filtered for the sockets of the `vivaldi-bin` processes using the command shown in @list-filteredSockstat. This shows that the process `vivaldi-bin` handles around $410$ open sockets.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/netstat2.png", width: 80%),
    caption: "Sockstat output."
  )<list-filteredSockstat>
])

#v(0.5cm)

=== Finding the Unique Artefact in Memory
#v(0.5cm)

To find the unique artefact I searched for the string `giphy-3348127193.gif` in memory using the command shown in @list-gifSearch.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ strings ram.dump | grep giphy-3348127193.gif

      giphy-3348127193.gif
      /home/philip/Pictures/giphy-3348127193.gif
      [...]
    ```,
    caption: "Searching for unique artefact in memory."
  )<list-gifSearch>
])

#v(0.5cm)

The simple string search already revealed the full path of the opened image, see @list-gifSearch. Opening the file path in the default image viewer application indeed shows the correct `gif` image, see @fig-uniqueArtefactFound.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/openiArtifact.png", width:80%),
    caption: "Unique artefact found in memory."
  )<fig-uniqueArtefactFound>
])

#pagebreak()