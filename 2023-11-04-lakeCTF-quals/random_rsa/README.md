# RandomRSA (crypto)

## Introduction

In the task we get [source code](randomrsa.py) of a relatively simple service.
It generates a random RSA key and encrypts the flag.
We don't know the primes or modulus, only public exponent.
Generation of the first prime is done in verbose way and prints the discarded non-prime values from the random.

## Analysis

The vulnerability here comes from the fact that python's random MT is not cryptographically secure and its state can be recovered if we can observe enough outputs.
Specifically 624*32 bits have to be observed in order to recreate the internal state of the generator.

## Solution

We can use some existing libraries designed for the purpose of recovering python MT rand state like: https://github.com/tna0y/Python-random-module-cracker

What we get from the server are 1024 bit numbers, so we need to do some splitting to make it compatible with the library:

```python
def crack(numbers, bits):
    from randcrack import RandCrack
    rc = RandCrack()
    split_numbers = []
    for n in numbers:
        v = hex(n).replace("0x", "").rjust(bits // 4, "0")
        for c in chunk(v, 8)[::-1]:
            split_numbers.append(int(c, 16))
    for n in split_numbers[-624:]:
        rc.submit(n)
    return rc
```

This function will split list of numbers with n-bits into 32-bit pieces and feed them into randcrack.

We can make a quick sanity check:

```python
def sanity2():
    bits = 1024
    numbers = [random.getrandbits(bits) for _ in range(100)]
    rc = crack(numbers, bits)
    for i in range(1000):
        assert random.getrandbits(1024) == rc.predict_getrandbits(1024)
```

To verify it all works as expected.
The solution approach is:

1. Collect failed `p` values from server
2. Feed them to randcrack
3. Pick the next value for `p`
4. Loop until another prime is found, which is `q`

We can again verify this idea:

```python
def sanity3():
    bits = 1024
    numbers = []
    while True:
        p = random.getrandbits(bits)
        if isPrime(p):
            break
        else:
            numbers.append(p)
    while True:
        q = random.getrandbits(bits)
        if isPrime(q):
            break

    rc = crack(numbers, bits)
    expected_p = rc.predict_getrandbits(1024)
    while True:
        expected_q = rc.predict_getrandbits(1024)
        if isPrime(expected_q):
            break
    assert p == expected_p
    assert q == expected_q
```

Now that we have a locally working solution, we can plug in the real values:

```python
def solve():
    numbers = [
        12766930611583315295482024813942610377665812508134430129487862982299978199916813519399511353768814410575144267724125932387316294800212303044955328123020470620529675917183441180810217770892014771617517025345694610118556446022566196572285052310503855886767362635014778375753380396757925403290664779458958422163,
        88429105076667629574760256075580860989205628238426804773867513736076189831348492450684043505007160524026497052393879358581161644989364403408213095526467132297689364251187569157629952772696546582606638958879545757273564153379984811579024223267895771768499095135971290243491030766389850021721920085528281090836,
        48614832248159225043815595042098588723285747505563026281795199887129104169247639597240044887308903369544265367220434265666416517593932022935680120626084639780796391723702024608950760323896810552878582698739775058647155064458604662152051640042809607550589335551691782545327184365151773777504241751647866612959,
        140349391544015504160373097877480424599170113443271656284897775430255538565614222344301128384592536541835084240758923588054618590012002204937913948276588777208320377038591033965494227684016446203525955568539724380231735362817288194248354775876345913702087982886773240908374954416791097473818850120138202372351,
        81005388895513757630787072351166889917645988073030256801615644790918342680603976315980823762725753256970170034703569582058697488187906162397056681848385292625189401390064712672707196514733419641742149290131034676406506769160280570310918351093755619146136618297240370758768256980350576065769272405206171726194,
        93945835970888124018000506375594724489886688112815042942087339557395668049486292051552439189947214590879335855116905440844399991106382411011445115866811588738390374126989268429953917935154788350261775159901861811716396292291937443156692207605050423141250274920269446921184942101950694969469779516678942634293,
        1338203607964790086889741199465926950501282637303229698170435168559480097182161321094523811690549753573852836636374836488778676809836132911450298578602680658474238563789052717363941912067728292459479671446546067910966784880909375058852319261898736257599698587724782147579797801544972459732011354909593022491,
        117575856978452325234482054359768129857793104320200518901521573574192391570443690233764695021892590750723004444764686466903074347044511934835303545155814101687207308570797576257081704026684815028706578330329323898554929817610095523084354403632956244694397574512517917609143029417498413797789828952629255256958,
        14731393616799252070692734366378072104221113104924962062246358460324677971602701140385761965480788566665990737277527425563603252574233154013743539908307861913093445543244759108651585661720737719213799732365273037742410606628418715267176649975664426082267724054349388378227391882411208505146277218793156030443,
        73837519424734695067523831876346755648181970569460601246817979408569626909197682334525449101247773881760641082027484956348672505312405581951343856417543568062775721088270842710177081623005909920285267311036416900949626932565086205600247292028500851869189016949978223253143463506676857889240147792810474065873,
        8615974403567333541427948429252858169633132223943934185172320554246625268532522832073177614703057674823776548413145540433076457434468167068483219269776266800077816937362282048851958535902022727530968561947530553499245716022630474501584355938095918225424017574713490174963822005942191358908534067389078224115,
        1145935141578780647388819123653316424325333337831788369666196436235380367838760445553411635804306364407790074815747745683709435924213614948666374822616463509215685417246021991981590467361989751717000517485907044558599248079594792540545141309345129063741096926871786220022490359671569280463374255407693321410,
        115667204834780084766535506181131038942105613966026865604777990636308960602915506871735187095416441092569382864547112010827238193928360869759169435209226763611499233451835783619284734409215091986043304681627101444180654416224971953476500036440510363692785443754379499078355517422194808140209028092969988415812,
        36213336696481037671240055568447367285608873700093541301587185463525210078474547391031230658486029066206897731204935825401580998377835153942601251042502905972008950705145402289493131438032291483440728926334132932978929477792606865341575371428957956917884845493609354548015495129846498485497750760229316059674,
        121148139236100924616802209886559799300609709542037357378909217206479816991656995361364665103492536306729388566018907602139631326413546458545628259600775368707573665119432167680035740457738738169517128557950002340029271812235100027033341229287381058276638900311775075845987515069561910879387945383844456642040,
        11228000989258900154723376347317574398731933052564479806290829920990015954149927784462406481551561236183556564375746627547767934234870619316375533128009176188767479431570311385283793183600673335594524146086387485840411399745191820967948795740661774328892408080879105353910391267274971090079298372691880778259,
        168050581182139701804219397044361713864253586566588540593208413778805007831723406103148008281984817569819540865831640285701786337776478192392900028141052982026855764311772351063577995691254255285589873054837163001191471342574522102408829199739361295133375148460152423845086768743751724827574599451543243886923,
        21909696045852466396316260351615917017295606450775372586424828385685021064802100041943013420592260919936607952576233001179523587577069984329314971193764357614459725883928779803190673770067268248746443933496765371120128351807151231314525837208020931122346301425378781055744818862406948711013208628782200976141,
        129225134672731497590538617086504035851474698693858501855737567076210991485037721605637181443760092556340152588175821108821617448395726999416987111318964279117091922996091465342708317153238252884380771139618542916442073692610691262951551157846971412820759733632380914924096372987861493539168431232903872319554,
        19768461992269544791694383572109935641876206336671273903100283033111482584915930153307505401078417109660419551718322216257180217274728505393520104570640823695207186879277222339628971096936294653690124146763020817890184580286414553005478032080420816746920435613342978027700758151052369464924504310995933319838]
    rc = crack(numbers, 1024)
    p = rc.predict_getrandbits(1024)
    assert isPrime(p)
    ct = 10638935173194351395188620653292213605262937284634766102192920852314066851575126853933179637604467108900163365225471312125045415859337107819842568136510644298343356034734280596894366970543687301174099525809142798651496978127575367447583421104476200080874651699727167025177986478491721089222216384673362448019579339651511838089617987458196567829270374597099002379128397733751810435584821789169066993338216648039030618244308616143848248346813665124910400446319928299855978283396480661375919872035308487118282665316124022019941824882774229058556850163417220917822003372491527196152327921844718503462976414958028158918997
    while True:
        q = rc.predict_getrandbits(1024)
        if isPrime(q):
            break
    print(p, q)
    d = modinv(65537, (p - 1) * (q - 1))
    print(long_to_bytes(pow(ct, d, p * q)))
```

and we get `EPFL{w0w_s0_much_r4nd000o0oo0om}`