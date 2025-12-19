= Assignment - Part 2
#v(0.5cm)

First we downloaded and unzipped the provided memmory dump file. The Sha256 checksum of the file is: `fee4a87527509ed8a67c51a2b3e21a74ae52739e0d69020312180339cfd79e3b`.

== Basic Memory Analysis
#v(0.5cm)

I first collected some basic information about the memory dump using the `windows.info` plugin, see @list-wininfo.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f physmem.raw windows.info

      Volatility 3 Framework 2.27.0
      Progress:  100.00               PDB scanning finished
      Variable        Value

      Kernel Base     0xf80420a00000
      DTB     0x1ae000
      Symbols symbols/windows/ntkrnlmp.pdb/7C85537A944BEF2014AE251FDEA1C590-1.json.xz
      Is64Bit True
      IsPAE   False
      layer_name      0 WindowsIntel32e
      memory_layer    1 FileLayer
      KdVersionBlock  0xf804216099a0
      Major/Minor     15.22621
      MachineType     34404
      KeNumberProcessors      2
      SystemTime      2023-01-09 22:17:11+00:00
      NtSystemRoot    C:\Windows
      NtProductType   NtProductWinNt
      NtMajorVersion  10
      NtMinorVersion  0
      PE MajorOperatingSystemVersion  10
      PE MinorOperatingSystemVersion  0
      PE Machine      34404
      PE TimeDateStamp        Mon Jul  5 20:20:35 2100
      ```,
          caption: "vol -f physmem.raw windows.info"
  )<list-wininfo>
])

#v(0.5cm)

The output shows that the memory dump is from a Windows 11 system (Build `22621`) running on a 64-bit architecture with 2 processors. The system time at the time of the memory dump was `2023-01-09 22:17:11+00:00`.

== Finding SIDs and Credentials
#v(0.5cm)

Using the command shown in @list-getSIDs I extracted all SIDs found in the memory dump.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f physmem.raw windows.getsids.GetSIDs > sids.txt
      ```,
          caption: "vol -f physmem.raw windows.getsids.GetSIDs"
  )<list-getSIDs>
])

#v(0.5cm)

The output file `sids.txt` contained multiple SIDs, see @fig-sids.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/sids.png", width: 80%),
    caption: "Extracted SIDs from memory dump"
  )<fig-sids>
])

#v(0.5cm)

Next I tried to extract credential hashes from the dump, see @list-credHashes.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f physmem.raw windows.registry.hashdump
      
      Volatility 3 Framework 2.27.0
      Progress:  100.00               PDB scanning finished
      User    rid     lmhash  nthash
      WARNING  volatility3.plugins.windows.registry.hashdump: Hbootkey is not valid
      ```,
          caption: "vol -f physmem.raw windows.registry.hashdump"
  )<list-credHashes>
])

#v(0.5cm)

As shown in the output, I was not able to extract any credential hashes from the memory dump since the `Hbootkey` is not valid. We were provided a valid Hbootkey in the assignment description, so I added an early return statement to the plugins `Python` file, as shown in @list-hbootkeyFix, returning the valid `Hbootkey`. The plugin can be found in the Volatility 3 installation directory under `volatility3/plugins/windows/registry/hashdump.py`.

#v(0.5cm)

#align(center, block[
  #figure(
    ```python
        @classmethod
        def get_hbootkey(
            cls, samhive: registry_layer.RegistryHive, bootkey: bytes
        ) -> Optional[bytes]:
            sam_account_path = "SAM\\Domains\\Account"
        return b"\xBC\xF8\x54\x8E\xAE\x42\x90\x0B\xED\xA0\xF1\x50\xE1\x65\x04\xB5"
      ```,
          caption: "Fixing Hbootkey retrieval in windows.registry.hashdump plugin"
  )<list-hbootkeyFix>
])

#v(0.5cm)

With the correct Hbootkey in place I re-ran the `windows.registry.hashdump` plugin, see @list-credHashesFixed.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f physmem.raw windows.registry.hashdump
      
      Volatility 3 Framework 2.27.0
      Progress:  100.00               PDB scanning finished
      
      User    rid     lmhash  nthash

      Administrator 500 aad3b435b51404eeaad3b435b51404ee 31d6cfe0d16ae931b73c59d7e0c089c0
      Guest 501 aad3b435b51404eeaad3b435b51404ee 31d6cfe0d16ae931b73c59d7e0c089c0
      DefaultAccount 503 aad3b435b51404eeaad3b435b51404ee 31d6cfe0d16ae931b73c59d7e0c089c0
      WDAGUtilityAccount 504 aad3b435b51404eeaad3b435b51404ee 46cbf54c64b31b778c5019c7a4c90970
      Spongebob 1001 aad3b435b51404eeaad3b435b51404ee d8ce5e07ae6dd698222c75def3dc23f6

      ```,
          caption: "vol -f physmem.raw windows.registry.hashdump after Hbootkey fix"
  )<list-credHashesFixed>
])

#v(0.5cm)

The table below lists the extracted credential hashes from the memory dump in a more organized format.

#v(0.5cm)

#set table(
  stroke: (x, y) => if y == 0 {
    (bottom: 0.7pt + black)
  },
  align: (x, y) => (
    if x > 0 { center }
    else { left }
  )
)

#align(center, block[
  #table(columns: 4, 
    table.header[User][RID][LM Hash][NT Hash],
    [Administrator], [500], [aad3b435b51404eeaad3b435\
    b51404ee], [31d6cfe0d16ae931b73c59d7\
    e0c089c0],
    [Guest], [501], [aad3b435b51404eeaad3b435\
    b51404ee], [31d6cfe0d16ae931b73c59d7\
    e0c089c0],
    [DefaultAccount], [503], [aad3b435b51404eeaad3b435\
    b51404ee], [31d6cfe0d16ae931b73c59d7\
    e0c089c0],
    [WDAGUtilityAccount], [504], [aad3b435b51404eeaad3b435\
    b51404ee],[46cbf54c64b31b778c5019c7\
    a4c90970],
    [Spongebob], [1001], [aad3b435b51404eeaad3b435\
    b51404ee], [d8ce5e07ae6dd698222c75de\
    f3dc23f6],
    )
])

#v(0.5cm)

The first three NT hashes all the well-known blank value.
My attempts to recover Spongebob's password using hashcat with different dictionaries or brute-forcing mode were not successful.

== Processes and Network Connections
#v(0.5cm)

Using the `windows.pslist` plugin I listed all running processes found in the memory dump, see @fig-winPslist.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/win_pslist.png", width: 80%),
    caption: "vol -f physmem.raw windows.pslist"
  )<fig-winPslist>
])

#v(0.5cm)

The output shows the first process was startet at `023-01-09 21:47:13.000000 UTC`, which is approximately 30 minutes before the memory dump was aquired at `2023-01-09 22:17:11+00:00`, as shown in the `windows.info` output.
The list of processes also contains multiple active `firefox.exe`, `tor.exe` and `msedge.exe` processes. There are also an open `notepad.exe` process, `msteams.exe` and `Lwinpmem_mini_x` which is likely the memory acquisition tool.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/firefox.png", width: 80%),
    caption: "Example firefox.exe processes"
  )<fig-firefox>
])

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/winpmem_proc.png", width: 80%),
    caption: "WinPmem process"
  )<fig-winPmem>
])

#v(0.5cm)

Running the `windows.psscan.psscan` plugin did not reveal any additional information.\

Running `windows.netstat.Netstat` and `windows.netscan.Netscan` listed all open network connections, see @fig-winNetstat and @fig-winNetscan.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/netstat.png", width: 80%),
    caption: "vol -f physmem.raw windows.netstat output"
  )<fig-winNetstat>
])

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/netscan.png", width: 80%),
    caption: "vol -f physmem.raw windows.netscan output"
  )<fig-winNetscan>
])

#v(0.5cm)

For better readability I only show the connections with the state `ESTABLISHED` in @fig-winNetstat and @fig-winNetscan.

Next I looked at the commandline arguments of the running processes using the `windows.cmdline.CmdLine` plugin, see @list-cmdline.

#v(0.5cm)

#align(center, block[
  #figure(
        ```bash
    $ vol -f physmem.raw windows.cmdline.CmdLine
      ```,
    caption: "vol -f physmem.raw windows.cmdline.CmdLine"
  )<list-cmdline>
])

#v(0.5cm)

As shown in the output, I was able to see a variety of running processes with different commandline arguments, see @fig-winCmdLine.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/cmdline.png", width: 80%),
    caption: "vol -f physmem.raw windows.cmdline.CmdLine output"
  )<fig-winCmdLine>
])

#v(0.5cm)

Filtering the output let me link some `msedge.exe` processes to running `msteams.exe` processes, Edge seems to be used as an embeeded browser to display Teams content.

Most interesting was the running `notepad.exe` process, which had the commandline argument `C:\Users\Spongebob\Desktop\password.txt.txt`, see @fig-notepadCmd. This indicates that the user `Spongebob` had a text file named `secret.txt` open on his desktop at the time of the memory dump.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/notepad.png", width: 80%),
    caption: "Notepad command line argument"
  )<fig-notepadCmd>
])

#v(0.5cm)

== Analyzing Files in the Dump
#v(0.5cm)

To analyze files present in the memory dump I used the `windows.filescan.Filescan` plugin to list all file objects found in memory, see @fig-filescan.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/filescan.png", width: 80%),
    caption: "Filescan output"
  )<fig-filescan>
])

#v(0.5cm)

I dumped the files with the command shown in @list-dumpFiles.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vol -f physmem.raw -o files/ windows.dumpfiles.DumpFiles
      ```,
          caption: "Dumping files from memory dump"
  )<list-dumpFiles>
])

#v(0.5cm)

The dumped files contain quite a lot of cookie databases and `-wal` files which are used by modern browsers to store session data, visited domains can be viewed this way.

Looking at those dumped `sqlite` databases I was able to see some of the databases containing cookies, see @fig-sqliteCookies.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/dump_sqllite.png", width: 80%),
    caption: "Dumped cookie databases"
  )<fig-sqliteCookies>
])

#v(0.5cm)

Looking at all the dumped databases I could also see databases containing visited URLs, see @fig-sqliteVisited.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/dump_sqlite2.png", width: 80%),
    caption: "Dumped sqlite databases"
  )<fig-sqliteVisited>
])

#v(0.5cm)

Using the `strings` command I searched the databases for interesting URLs, I could see that close to the memory dump the user:

- Searched for `WinPmem`
- Visited the `WinPmem` Github
- Downloaded the `Tor Browser`
- Visited Hacker News 
- And watched a YouTube video ` Rick Astley - Never Gonna Give You Up`

See @fig-nevergonna for a screenshot displaying the console output.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/nevergonna.png", width: 80%),
    caption: "Strings output showing visited URLs"
  )<fig-nevergonna>
])

#v(0.5cm)

Similar outputs exist for the `Tor Browser` and `Microsoft Edge`.

I was not able to find the contents of the `password.txt.txt` file. I was able to extract its contents with a more basic approch using `strings`, see @list-passwordTxt.

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ strings physmem.raw | grep "password.txt.txt" -A 5 | less
      ```,
          caption: "grepping for password.txt.txt in memory dump"
  )<list-passwordTxt>
])

#v(0.5cm)

I was able to extract the following password from the output: `SuP3rS3crEt2023!`, see @fig-passwordTxt.

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/pw.txt.tx.png", width: 40%),
    caption: "Extracted password from password.txt.txt"
  )<fig-passwordTxt>
])

I was not able to confirm that this is the password related to the NT hash of user `Spongebob`.

== Questions
#v(0.5cm)

+ What information can you extract about the operating system?
  - The memory dump is from a Windows 11 system (Build `22621`) running on a 64-bit architecture. The system time at the time of the memory dump was `2023-01-09 22:17:11+00:00`.

+ What happened at the time of the RAM dump?
  - The system showed several browsers running at the same time, notably Firefox and Tor Browser.
  - Temporary files indicate that web pages such as GitHub, Hacker News, and YouTube were likely still open.
  - Multiple network connections were active, including an active Tor network session.
  - A Notepad window was open containing a file named `password.txt.txt`.
  - Additional applications were running, including Microsoft Teams, along with various background services (for example, OneDrive).
  - A command-line session was active, and a memory dump utility was running.

+ What is the user SID?
  - `S-1-5-21-2607170198-3457296929-47938352-1001`

+ Can you find/crack the user password (and get a hint who sent you the RAM dump)?
  - The NTLM password hash could be extracted; however, it was not successfully cracked, and the contents of the `password.txt.txt` file could not be reliably recovered.
  - Memory dump analysis identified the string SuP3rS3crEt2023! as a potential password.
  - It is likely that the memory dump was created by the user Spongebob.