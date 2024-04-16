# Implementovaná Funkcionalita
### Filtrování pomocí:
- Síťového rozhraní - `-i interface | --interface interface`
- TCP segmentu - `--tcp|-t`
- UDP datagramu - `--udp|-u`
- Čísla portu - `-p|--port-source|--port-destination port`
- ICMPv4 packetů - `--icmp4`
- ICMPv6 packetů - `--icmp6`
- ARP protokolu - `--arp`
- NDP packetů - `--ndp`
- IGMP packetů - `--igmp`
- MLD packetů - `--mld`
- Maximální počet packetů pro výpis - `-n num`, kde `num` je uživatelem zadané číslo 

### Vypisování podle daného zadání
`timestamp`: čas (RFC 3339 formát)

`src MAC`: MAC adresa zdroje

`dst MAC`: MAC adresa destinace

`frame length`: délka (byte)

`src IP`: IP addresa zdroje

`dst IP`: IP addresa destinace

`src port`: číslo portu zdroje

`dst port`: číslo portu destinace

`byte_offset`: hex dump

## Závěr
Závěrem projekt splňuje všechny zadané požadavky a nejsem si vědom žádných nedostatků.