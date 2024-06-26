# Dokumentace k IPK projektu 2 - ZETA: Network sniffer
### Autor: Lukáš Píšek (xpisek02)
## Obsah <a name="obsah"></a>
- [Obsah](#obsah)
- [Úvod](#uvod)
- [Implementace](#impl)
    - [Použité nástroje](#impl1)
    - [Začátek programu](#impl2)
    - [Funkcionalita](#impl3)
        - [OnPacketArrival](#impl3-1)
        - [Formátování výstupu](#impl3-2)
- [Testování](#test)
- [Makefile](#make)
- [Závěr](#end)
- [Bibliografie](#src)

## Úvod <a name="uvod"></a>
Cílem řešeného projektu bylo vytvořit konzolovou aplikaci, která bude odposlouchávat packety na síti a vypisovat informace o nich na `stdout`.
## Implementace <a name="impl"></a>
### 1. Použité nástroje <a name="impl1"></a>
Na vypracování tohoto projektu jsem použil následující nástroje:
-	Operační systém – Windows 11 pro celkový vývoj a částečně [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux) (Ubuntu) pro testování
-	Programovací jazyk – C#
-	IDE – [Rider](https://www.jetbrains.com/rider/) pro vývoj na Windows a [VSCode](https://code.visualstudio.com) pro vývoj na Linux.
-   [Wireshark](https://www.wireshark.org) - nástroj pro analýzu síťového provozu
-   Verzovací systém – Git
-	Jako pomoc při programování a pro obecné otázky – Github Copilot
### Začátek programu (Metoda `Main()`) <a name="impl2"></a>
Za pomocí knihovny `CommandLine` vlastní třídy `ArgParserOptions` se jako první věc zpracujou argumenty programu zadané uživatelem. 
Následně se vytvoří nová instance vlastní třídy `Sniffer`, nastaví se metoda pro ukončení programu pomocí klávesové zkratky a poté se zavolá metoda `SniffingSetup()`, která mimo jiné předá řízení programu již dříve zmíněné instanci třídy `Sniffer`.
### Funkcionalita <a name="impl3"></a>
Po zavolání metody `SniffingSetup()` se nejprve ošetří, zda se má vykonat samotné odposlouchávání packetů na zadaném síťovém rozhraní, nebo pouze vypsat list všech možných rozhraní.
Pokud se má vykonat odposlouchávání, tak se zavolá metoda `StartSniffing()`, která otevře dané rozhraní na promiskuitním režimu, nastaví se, co se má stát při získání packetu a nakonec se začne odposlouchávat veškerá komunikace na daném rozhraní.
Program v tuto chvíli vstoupí do nekonečného `while` cylku, který se ukončí pouze po nastavení podmínky `_run` na false. Tento cyklus má v sobě také uspání na 50 milisekund aby se zbytečně moc nezatěžoval procesor.
#### OnPacketArrival <a name="impl3-1"></a>
Pokud program zachytí packet, provede se kontrola zda by vypsání tohoto packetu nepřekročil jejich maximální počet. Následně se provede filtrace packetu pomocí zadaných argumentů. Tato filtrace se provede pokusným extrahováním daného typu a následnou kontrolou, zda tato extrace neobsahuje `null` hodnotu.
Filtrace je možná za pomocí následujících hodnot
- Typy packetů
    - TCP (volitelně s číslem portu)
    - UDP (volitelně s číslem portu)
    - ICMPv4
    - ICMPv6 (echo request/reply)
    - ARP
    - NDP
    - IGMP
    - MLD
- Možnost stanovit počet vypsaných packetů 

Pokud packet není ani jeden typ z výše uvedených (například lldp), přeskočí se.

#### Formátování výstupu <a name="impl3-2"></a>
Po správném vyfiltrování se informace o daném packet pošlou do statické metody `FormatOutput()` ve vlastní třídě `OutputFormatter`. V této třídě jsou mimo již dřívě zmíněnou metodu také pomocné metody, které zjistí různé informace o daném packetu. Například čas, MAC adresu, IP adresu...
Všechny tyto metody nakonec pomůžou vrátit výsledný `string` naformátovaný podle zadání a inkrementuje se počet vypsaných packetů.
Pokud daný packet nemá nějakou informaci (například port), vypíše se namísto něho `None`.
## Testování programu <a name="test"></a>
Testování nejprve proběhlo aplikováním stejných filtrů jak v programu, tak v aplikaci Wireshark a následnou korelací zachycených packetů. 

![Porovnání packetů](./src/packet.png) *Porovnání výstupu programu a packetu zachyceném ve wiresharku*

Po tomto jednoduchém testu byl vytvořen primitivní skript na testování různých hraničních případů, který byl schopný posílat packety různého typu, jejichž zachycení se poté kontrolovalo v programu.

## Makefile používání <a name="make"></a>
- `make` Kompilace a vytvoření spustitelného souboru `ipk-sniffer`
- `make build` Překlad programu 
- `make publish` Kompilace a vytvoření spustitelného souboru `ipk-sniffer`
- `make run ARGS="arg1 arg2..."` Spuštení programu s argumenty `arg1` `arg2`...
- `make clean` Vyčištění adresáře + smazání vytvořených složek a souborů 

## Závěr <a name="end"></a>
Tento projekt mě naučil různě typy síťových packetů a jak je zpracovávat, pokud z nich budu potřebovat dostat nějaké konkrétní informace.
Naučil jsem se pracovat s knihovnou `SharpPcap`.
Tímto projektem jsem si osvěžil práci s OOP a C#

## Bibliografie <a name="src"></a>
* sharppcap public repository: https://github.com/dotpcap/sharppcap
* commandline public respository: https://github.com/commandlineparser/commandline
* TCPDUMP/LIBPCAP public repository: http://www.tcpdump.org/
* Library http://packetfactory.openwall.net/projects/libnet/
* [RFC 792] J. Postel. *INTERNET CONTROL MESSAGE PROTOCOL*. [online]. September 1981. [cited 2024-04-21]. DOI: 10.17487/RFC0792. Available at: https://datatracker.ietf.org/doc/html/rfc792
* [RFC 4443] Mukesh Gupta and Alex Conta and M. Gupta, Ed. *Internet Control Message Protocol (ICMPv6)* [online]. March 2006. [cited 2024-04-21]. DOI: 10.17487/RFC4443 Available at: https://datatracker.ietf.org/doc/html/rfc4443
* [RFC 826] David C. Plummer. *An Ethernet Address Resolution Protocol* [online]. November 1982. [cited 2024-04-21]. DOI: 10.17487/RFC0826 Available at: https://datatracker.ietf.org/doc/html/rfc826
* [RFC 5952] S. Kawamura and M. Kawashima. *A Recommendation for IPv6 Address Text Representation* [online]. August 2010. [cited 2024-04-21]. DOI: 10.17487/RFC5952. Available at: https://datatracker.ietf.org/doc/html/rfc5952
* [RFC 3339] G. Klyne and C. Newman. *Date and Time on the Internet: Timestamps* [online]. July 2002. [cited 2024-04-21]. DOI: 10.17487/RFC3339. Available at: https://datatracker.ietf.org/doc/html/rfc3339