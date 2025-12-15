# Test Exam 2 - Digitale Forensik

### Which of these attributes are mandatory for all MFT entries?
- [X] \$INDEX_ROOT (bei Directories)/$DATA (Bei Dateien)
- [X] $STANDARD_INFORMATION
- [X] $FILE_NAME

### Which job is a good prequisite to easily become a forensics expert?
- [ ] Dentist
- [X] System administrator
- [ ] Teacher
- [X] Network engineer

### What statements are true about UserAssist?
- [ ] Stores each program execution date
- [X] Stores the last program execution date
- [X] Stores the number of program executions
- [X] Is saved in the registry

### What sizes are currently used in the NTFS file system?
- [X] 4096 bytes sector size (used to be 512 bytes) and 4096 bytes cluster size
- [ ] 4096 bytes sector size and 4096 bytes cluster size (used to be 512 bytes)
- [ ] 512 bytes sector size and 512 bytes cluster size
- [ ] 512 bytes sector size and 4096 bytes cluster size

### Was besagt der Überwälzungsgrundsatz?
- [X] bezahlt werden muss zuerst vom Auftraggeber
- [X] der Auftraggeber kann das bezahlte Geld auch an den Verlierer eines Prozesses überwälzen

### What statements are correct concerning forensics in companies? (WAS SOLL DIESE FRAGE?)
- Es gibt einen fixen ablauf dem jeder folgen muss
- Guides by NIST have to be applied 1:1
- Guides by NIST can be applied mixed
- Guides have to be adjusted to fit the company

### What is the advantage of looking into data of previous incidents?
- [ ] Data can be restored like in a backup 1:1
- [X] Previous incident data can help and reduce work enormously when analyzing the current incident

### What statements are true concerning the Gutachten and Befund?
- [X] Der Befund stellt alle relevanten Tatsachen, aus denen die spaeteren Schlussfolgerungen gezogen werden, dar
- [X] Der Befund ist die Grundlage fuer das Gutachten im engeren Sinn Alle Schluesse und Aeusserungen, die sich darin befinden, muessen auf im Befund dokumentierten Tatsachen fundieren

### What statements are true concerning evidence
- [ ] A judge has to acknowledge all evidences
- [X] Evidence consisting of reports by laypersons has to be acknowledged
- [X] Evidence consisting of reports has to be acknowledged

### What are the disadvantages of using DMA?
- [X] DMA changes the RAM state
- [X] One has to carry a DMA tool with him
- [ ] DMA depends on the OS
- [ ] DMA influences paging

### What are the advantages of using DMA?
- (More) OS-independent than software-based dumps (no need to run a memory dumper inside the target OS; can work even if the OS is unstable or compromised).
- Can bypass some user-mode / kernel-mode restrictions that would block normal acquisition (e.g., locked screen, lack of admin rights), depending on platform protections.
- Fast acquisition (high throughput over the bus; good for capturing volatile data quickly).
- Less reliance on the target storage (no need to write a dump file to the suspect disk, reducing disk artifacts).
- Can capture otherwise hard-to-get volatile artifacts (keys, decrypted content, network/session state) as they exist in RAM at that moment.

### What about documentation?
- [X] is the most important thing
- [ ] is a hard thing that is easy to be done wrong
- [X] saves a forensics guy from being accused to have manipulated the data

### Software vs hardware RAM acquisition?
- [X] Software is cheaper
- [ ] Software is OS-independent

### What statements are true concerning Vtypes in Volatility?
- [X] Maps C types to Python
- [ ] Supports as many data types as C provides
- [X] Are used to model a specific OS/hardware architecture
- [ ] Is needed to execute the main Python script (vol.py)

### You see a locked PC that has no port to use DMA (Firewire, etc.). What do you do?
- [X] Use a cold boot attack
- [X] Turn the PC off and analyze the HDD in the lab
- [ ] Use FTK3
- [ ]Use Volatility
- Bonus Info: I would use the mobile forensics powersupply to keep the PC powered and transport them to the lab.

### Which cryptographical functions are used to achieve integrity?
- [ ] AES with ECB
- [ ] AES with CBC
- [X] Cryptographical hash functions
- [ ] Fuzzy hashing

### Which techniques did Max Butler (from the book Kingpin) in the example use? He...
- [X] hacked into WiFis
- [X] did stack based buffer overflows
- [ ] captured RAM
- [ ] used Tor for hacking

### Concerning HDD analysis, which statements are true?
- [x] Using hardware write blockers is mandatory
- [ ] Using hardware write blockers is optional
- [ ] Using software write blockers is sufficient
- [X] There exists a hardware write blocker which can handle RAID

### Which of those file attributes exist?
- [X] Modified
- [ ] Updated
- [X] Created
- [ ] Moved

### When a file is deleted on hard disk, what does change?
- [ ] The file is overwritten multiple times
- [X] The MFT entry is marked as deleted
- [ ] The bitmap of the corresponding sectors is set to 1
- [x] The bitmap of the corresponding sectors is set to 0

### Welche dieser Punkte sind in einem Gutachten unzulässig?
- [X] Rechtsbelehrungen anzubieten
- [X] Unüberprüfbare Behauptungen

### Which statements are true about RAM acquisition?
- [X] Acquisition is not repeatable
- [X] May provoke paging
- [X] Is invasive (RAM regions get overwritten)


### Which commands do you use to analyse processes, when doing an forensic analysis?
- [X] psscan
- [X] pstree
- [X] pslist