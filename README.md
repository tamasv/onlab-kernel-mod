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

###Referencia
[The Implementation of Passive Covert Channels in the Linux Kernel](ftp://ftp.pastoutafait.org/pdf/passive-covert-channels-linux.pdf)

##Linux kernel modul implementáció
TODO: Szöveg

###Feladatok
- [] Betölthető kernel modul, ami netfilter hookot használ
- [] A kernel modul felismeri és parseolja a dns csomagokat
- [] Beszúr egy cname rekordot egy visszaadás elött álló cname/a rekord helyett, majd kérdésre a cname/a rekordot küldeni
- [] Kibontja a bejövő request id-jában szereplő kódolt információt
- [] Userland kommunikáció

