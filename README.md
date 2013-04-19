onlab-kernel-mod
================
##DNS üzeneteken alapuló passzív covert channel implementációja

###Feladatkiírás
Minden internetes kommunikáció állandó velejárója, hogy DNS kérdéseket
küldünk és DNS válaszokat kapunk. Az utóbbi években többször lehetett
hallani olyan rosszindulatú programokról, ahol a fertőzött gép DNS
üzenetekkel kommunikál: a rosszindulatú kód a  DNS üzenetekeben kódoltan
küld információt. Ilyen módon lehet vezérelni botnetben résztvevő
gépeket, vagy ilyen módon lehet egy-egy gépen tárolt információt
kiszivárogtatni, a gépek mikrofonját lehallgatásra használni stb.
Az eddig nyilvánosságra került esetekben a DNS információ rendszerint
egy-egy speciális, erre a célra delegált domain neveit használta, vagy
ilyen domain-ek egy-egy előre kiválasztott halmazát. Ha azután fény
derült a gonosz kód működésére  ezeket domain regisztrációkat jogi úton
felfüggesztették.

Lehetséges a DNS üzenetekbe más módon is rejtett kommunikációs csatornát - covert channel-t - implementálni. Különösen tág lehetőségek nyílnak
akkor, ha a támadó a kliensek által használt rekurzív névszervernek is
birtokában van, azt is megfertőzte.

Példa implementációval demonstrálja, hogy fertőzött rekurzív DNS szerver
és fertőzött kliensek között olyan covert channel-t lehet implementálni,
ami nem használ jellemző DNS neveket, és így igen nehezen
felderíthető. Az önálló labor feladatban a tervezés és az egyik oldal
implementálása a cél, későbbi fázisokban kerülhet sor a teljes
implementációra, elemzésekre és összehasonlításokra.

###Protocol
DNSID mező használata
<pre>
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|ACT|Packet No. |     DATA      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
</pre>
#####ACT:
<ul>
<li>00 - No-op</li>
<li>01 - Új adat átvitel kezdete (Start)</li>
<li>10 - Adat átvitel közben</li>
<li>11 - Adat átvitel vége (utolsó csomag)</li>
</ul>
#####Packet No.:

Az adott DATA csomag hányadik a sorban. 6 bit (32) szám, ami körbe is tud fordulni. Csak akkor ir ki server oldalon egy bejövő dekódolt csomagot, ha nincs hiányzó sorszám az adott csomag és a legutoljára kiirt csomag közt. Ellenkező esetben bufferba kerül.
#####Data:
Ide kerül az adat (8 bit)

###Linux kernel modul implementáció
TODO: Szöveg

###Fileok:
TODO: Szöveg
####client-sender
Python program, mely egy tetszőleges fájlt elküld a DNS id-ba ágyazva
####utils/filecopy-test
C test program, ami egy fájlt feldarabol 8 bites blokkokra


###Feladatok
- [x] Betölthető kernel modul, ami netfilter hookot használ
- [x] A kernel modul felismeri és parseolja a dns csomagokat
- [x] C library, ami tetszőleges file-t feldarabol 8 bit-os blokkokra, és visszaadja az (c library)
- [x] Kliens oldali program
- [x] Kibontja a bejövő request id-jában szereplő kódolt információt
- [] Beszúr egy cname rekordot egy visszaadás elött álló cname/a rekord helyett, majd kérdésre a cname/a rekordot küldeni
- [] Userland kommunikáció

###Referencia
[The Implementation of Passive Covert Channels in the Linux Kernel](ftp://ftp.pastoutafait.org/pdf/passive-covert-channels-linux.pdf)
[Scapy](http://www.secdev.org/projects/scapy/)
[Netfilter hacking how-to](http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html)
