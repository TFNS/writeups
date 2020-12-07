# t3am_vi3w3r (forensics, 193p, 44 solved)

## Description

```
I was helping my grandfather clean his PC and I lost the flag in the process.

Find the flag.

Flag format DCTF{sha256}
```

In the task we get a 200MB pcap file (not attached).

## Task analysis

Very large pcap with lots of random stuff.
NetworkMiner didn't find anything very useful.
We spent a lot of time trying to see something in this. Finally we thought that maybe we should check what port usually is used by TeamViewer -> `5938`.

While we didn't have anything there, but there were some `VNC` packes on `5900`.

## Recovering data

If we now do follow tcp stream on this `tcp.stream eq 413` we get some large block of data, which seems ascii-printable, just separated by lots of nullbytes all around.

If we clear this up we get:

```
CCoonnttrraarryy  ttoo  ppooppuullaarr  bbeelliieeff,,  LLoorreemm  IIppssuumm  iiss  nnoott  ssiimmppllyy  rraannddoomm  tteexxtt..  IItt  hhaass  rroooottss  iinn  aa  ppiieeccee  ooff  ccllaassssiiccaall  LLaattiinn  lliitteerraattuurree  ffrroomm  4455  BBCC,,  mmaakkiinngg  iitt  oovveerr  22000000  yyeeaarrss  oolldd..  RRiicchhaarrdd  MMccCClliinnttoocckk,,  aa  LLaattiinn  pprrooffeessssoorr  aatt  HHaammppddeenn--SSyyddnneeyy  CCoolllleeggee  iinn  VViirrggiinniiaa,,  llooookkeedd  uupp  oonnee  ooff  tthhee  mmoorree  oobbssccuurree  LLaattiinn  wwoorrddss,,  ccoonnsseecctteettuurr,,  ffrroomm  aa  LLoorreemm  IIppssuumm  ppaassssaaggee,,  aanndd  ggooiinngg  tthhrroouugghh  tthhee  cciitteess  ooff  tthhee  wwoorrdd  iinn  ccllaassssiiccaall  lliitteerraattuurree,,  ddiissccoovveerreedd  tthhee  uunnddoouubbttaabbllee  ssoouurrccee..  LLoorreemm  IIppssuumm  ccoommeess  ffrroomm  sseeccttiioonnss  11..1100..3322  aanndd  11..1100..3333  ooff  ddee  FFiinniibbuuss  BBoonnoorruumm  eett  MMaalloorruumm  ((TThhee  EExxttrreemmeess  ooff  GGoooodd  aanndd  EEvviill))  bbyy  CCiicceerroo,,  wwrriitttteenn  iinn  4455  BBCC..  TThhiiss  bbooookk  iiss  aa  ttrreeaattiissee  oonn  tthhee  tthheeoorryy  ooff  eetthhiiccss,,  vveerryy  ppooppuullaarr  dduurriinngg  tthhee  RReennaaiissssaannccee..  TThhee  ffiirrsstt  lliinnee  ooff  LLoorreemm  IIppssuumm,,  LLoorreemm  iippssuumm  ddoolloorr  ssiitt  aammeett....,,  ccoommeess  ffrroomm  aa  lliinnee  iinn  sseeccttiioonn  11..1100..3322..

TThhee  ssttaannddaarrdd  cchhuunnkk  ooff  LLoorreemm  IIppssuumm  uusseedd  ssiinnccee  tthhee  11550000ss  iiss  rreepprroodduucceedd  bbeellooww  ffoorr  tthhoossee  iinntteerreesstteedd..  SSeeccttiioonnss  11..1100..3322  aanndd  11..1100..3333  ffrroomm  ddee  FFiinniibbuuss  BBoonnoorruumm  eett  MMaalloorruumm  bbyy  CCiicceerroo  aarree  aallssoo  rreepprroodduucceedd  iinn  tthheeiirr  eexxaacctt  oorriiggiinnaall  ffoorrmm,,  aaccccoommppaanniieedd  bbyy  EEnngglliisshh  vveerrssiioonnss  ffrroomm  tthhee  11991144  ttrraannssllaattiioonn  bbyy  HH..  RRaacckkhhaamm..

DDCCTTFF{{7744aa00ff3355884411ddffaa77eeddddff55aa8877446677cc9900ddaa333355113322aaee5522cc5588ccaa444400ff3311aa5533448833cceeff77eeaacc}}

WWhhyy  ddoo  wwee  uussee  iitt??

IItt  iiss  aa  lloonngg  eessttaabblliisshheedd  ffaacctt  tthhaatt  aa  rreeaaddeerr  wwiillll  bbee  ddiissttrraacctteedd  bbyy  tthhee  rreeaaddaabbllee  ccoonntteenntt  ooff  aa  ppaaggee  wwhheenn  llooookkiinngg  aatt  iittss  llaayyoouutt..  TThhee  ppooiinntt  ooff  uussiinngg  LLoorreemm  IIppssuumm  iiss  tthhaatt  iitt  hhaass  aa  mmoorree--oorr--lleessss  nnoorrmmaall  ddiissttrriibbuuttiioonn  ooff  lleetttteerrss,,  aass  ooppppoosseedd  ttoo  uussiinngg  CCoonntteenntt  hheerree,,  ccoonntteenntt  hheerree,,  mmaakkiinngg  iitt  llooookk  lliikkee  rreeaaddaabbllee  EEnngglliisshh..  MMaannyy  ddeesskkttoopp  ppuubblliisshhiinngg  ppaacckkaaggeess  aanndd  wweebb  ppaaggee  eeddiittoorrss  nnooww  uussee  LLoorreemm  IIppssuumm  aass  tthheeiirr  ddeeffaauulltt  mmooddeell  tteexxtt,,  aanndd  aa  sseeaarrcchh  ffoorr  lloorreemm  iippssuumm  wwiillll  uunnccoovveerr  mmaannyy  wweebb  ssiitteess  ssttiillll  iinn  tthheeiirr  iinnffaannccyy..  VVaarriioouuss  vveerrssiioonnss  hhaavvee  eevvoollvveedd  oovveerr  tthhee  yyeeaarrss,,  ssoommeettiimmeess  bbyy  aacccciiddeenntt,,  ssoommeettiimmeess  oonn  ppuurrppoossee  ((iinnjjeecctteedd  hhuummoouurr  aanndd  tthhee  lliikkee))..

WWhheerree  ddooeess  iitt  ccoommee  ffrroomm??

CCoonnttrraarryy  ttoo  ppooppuullaarr  bbeelliieeff,,  LLoorreemm  IIppssuumm  iiss  nnoott  ssiimmppllyy  rraannddoomm  tteexxtt..  IItt  hhaass  rroooottss  iinn  aa  ppiieeccee  ooff  ccllaassssiiccaall  LLaattiinn  lliitteerraattuurree  ffrroomm  4455  BBCC,,  mmaakkiinngg  iitt  oovveerr  22000000  yyeeaarrss  oolldd..  RRiicchhaarrdd  MMccCClliinnttoocckk,,  aa  LLaattiinn  pprrooffeessssoorr  aatt  HHaammppddeenn--SSyyddnneeyy  CCoolllleeggee  iinn  VViirrggiinniiaa,,  llooookkeedd  uupp  oonnee  ooff  tthhee  mmoorree  oobbssccuurree  LLaattiinn  wwoorrddss,,  ccoonnsseecctteettuurr,,  ffrroomm  aa  LLoorreemm  IIppssuumm  ppaassssaaggee,,  aanndd  ggooiinngg  tthhrroouugghh  tthhee  cciitteess  ooff  tthhee  wwoorrdd  iinn  ccllaassssiiccaall  lliitteerraattuurree,,  ddiissccoovveerreedd  tthhee  uunnddoouubbttaabbllee  ssoouurrccee..  LLoorreemm  IIppssuumm  ccoommeess  ffrroomm  sseeccttiioonnss  11..1100..3322  aanndd  11..1100..3333  ooff  ddee  FFiinniibbuuss  BBoonnoorruumm  eett  MMaalloorruumm  ((TThhee  EExxttrreemmeess  ooff  GGoooodd  aanndd  EEvviill))  bbyy  CCiicceerroo,,  wwrriitttteenn  iinn  4455  BBCC..  TThhiiss  bbooookk  iiss  aa  ttrreeaattiissee  oonn  tthhee  tthheeoorryy  ooff  eetthhiiccss,,  vveerryy  ppooppuullaarr  dduurriinngg  tthhee  RReennaaiissssaannccee..  TThhee  ffiirrsstt  lliinnee  ooff  LLoorreemm  IIppssuumm,,  LLoorreemm  iippssuumm  ddoolloorr  ssiitt  aammeett....,,  ccoommeess  ffrroomm  aa  lliinnee  iinn  sseeccttiioonn  11..1100..3322..

TThhee  ssttaannddaarrdd  cchhuunnkk  ooff  LLoorreemm  IIppssuumm  uusseedd  ssiinnccee  tthhee  11550000ss  iiss  rreepprroodduucceedd  bbeellooww  ffoorr  tthhoossee  iinntteerreesstteedd..  SSeeccttiioonnss  11..1100..3322  aanndd  11..1100..3333  ffrroomm  ddee  FFiinniibbuuss  BBoonnoorruumm  eett  MMaalloorruumm  bbyy  CCiicceerroo  aarree  aallssoo  rreepprroodduucceedd  iinn  tthheeiirr  eexxaacctt  oorriiggiinnaall  ffoorrmm,,  aaccccoommppaanniieedd  bbyy  EEnngglliisshh  vveerrssiioonnss  ffrroomm  tthhee  11991144  ttrraannssllaattiioonn  bbyy  HH..  RRaacckkhhaamm..

WWhheerree  ccaann  II  ggeett  ssoommee??

TThheerree  aarree  mmaannyy  vvaarriiaattiioonnss  ooff  ppaassssaaggeess  ooff  LLoorreemm  IIppssuumm  aavvaaiillaabbllee,,  bbuutt  tthhee  mmaajjoorriittyy  hhaavvee  ssuuffffeerreedd  aalltteerraattiioonn  iinn  ssoommee  ffoorrmm,,  bbyy  iinnjjeecctteedd  hhuummoouurr,,  oorr  rraannddoommiisseedd  wwoorrddss  wwhhiicchh  ddoonntt  llooookk  eevveenn  sslliigghhttllyy  bbeelliieevvaabbllee..  IIff  yyoouu  aarree  ggooiinngg  ttoo  uussee  aa  ppaassssaaggee  ooff  LLoorreemm  IIppssuumm,,  yyoouu  nneeeedd  ttoo  bbee  ssuurree  tthheerree  iissnntt  aannyytthhiinngg  eemmbbaarrrraassssiinngg  hhiiddddeenn  iinn  tthhee  mmiiddddllee  ooff  tteexxtt..  AAllll  tthhee  LLoorreemm  IIppssuumm  ggeenneerraattoorrss  oonn  tthhee  IInntteerrnneett  tteenndd  ttoo  rreeppeeaatt  pprreeddeeffiinneedd  cchhuunnkkss  aass  nneecceessssaarryy,,  mmaakkiinngg  tthhiiss  tthhee  ffiirrsstt  ttrruuee  ggeenneerraattoorr  oonn  tthhee  IInntteerrnneett..  IItt  uusseess  aa  ddiiccttiioonnaarryy  ooff  oovveerr  220000  LLaattiinn  wwoorrddss,,  ccoommbbiinneedd  wwiitthh  aa  hhaannddffuull  ooff  mmooddeell  sseenntteennccee  ssttrruuccttuurreess,,  ttoo  ggeenneerraattee  LLoorreemm  IIppssuumm  wwhhiicchh  llooookkss  rreeaassoonnaabbllee..  TThhee  ggeenneerraatteedd  LLoorreemm  IIppssuumm  iiss  tthheerreeffoorree  aallwwaayyss  ffrreeee  ffrroomm  rreeppeettiittiioonn,,  iinnjjeecctteedd  hhuummoouurr,,  oorr  nnoonn--cchhaarraacctteerriissttiicc  wwoorrddss  eettcc..
```

And now if we do `data[::2]` we have nice:

```

Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots
in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum
passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32.
The standard chunk of Lorem Ipsum used since the 1500s is reproduced below for those interested. Sections 1.10.32 and 1.10.33 from de Finibus Bonorum et Malorum by Cicero are also reproduced in their exact original form, accompanied by English versions from the 1914 translation by H. Rackham.
DCTF{74a0f35841dfa7eddf5a87467c90da335132ae52c58ca440f31a53483cef7eac}
Why do we use it?
It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using Content here, content here, making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for lorem ipsum will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).
Where does it come from?
Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots
in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum
passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of de Finibus Bonorum et Malorum (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance. The first line of Lorem Ipsum, Lorem ipsum dolor sit amet.., comes from a line in section 1.10.32.
The standard chunk of Lorem Ipsum used since the 1500s is reproduced below for those interested. Sections 1.10.32 and 1.10.33 from de Finibus Bonorum et Malorum by Cicero are also reproduced in their exact original form, accompanied by English versions from the 1914 translation by H. Rackham.
Where can I get some?
There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words
which dont look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isnt anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc.
```

And flag is: `DCTF{74a0f35841dfa7eddf5a87467c90da335132ae52c58ca440f31a53483cef7eac}`
