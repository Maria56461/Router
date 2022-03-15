
## Maria-Alexandra Barbu, 325CD 

# Tema 1- Protocoale de comunicatii
-------Implementare Router----------
-------------------------------------------------------------------------------

Structuri definite:
	- "route_table_entry" = o intrare a tabelei de routare 
	- "arp_entry" = o intrare a tabelei ARP 

Functii auxiliare:
	- "get_best_route" --> primeste o tabela de routare, o adresa IP careia i se
cauta match-ul si doi intregi (limitele [superioara si inferioara] ale
vectorului de intrari in tabela de routare). Face o cautare binara prin tabela
de routare pana cand gaseste intrarea din tabela care contine next_hop-ul
pachetului cu IP-ul destinatie primit de functie ca parametru. 
	- "get_arp_entry" --> cauta prin tabela ARP intrarea care contine mac-ul
corespunzator IP-ului primit ca parametru  

Am realizat alocarea dinamica a celor doua tabele, am creat o coada si am
facut parsarea tabelei de routare (un vector de structuri de tipul
"route_table_entry") folosind functiile "getline()" si "strtok". 

Flow-ul programului: 
	Se primeste un pachet "m". Se extrage header-ul Ethernet (si se verifica
corectitudinea extragerii). In functie de campul "ether_type" se verifica daca
este un pachet de tip IP sau ARP. Daca este un pachet IP si destinat
router-ului, se verifica daca este de tip ICMP (campul "protocol" trebuie sa
fie egal cu "1"). Daca nu este de tip ICMP, se da drop pachetlui, altfel se
verifica daca este un pachet de tip "ECHO request" (campul "type" trebuie sa
fie egal cu 8). Pentru pachetele de tip "ECHO request" se trimite raspuns de
tip "ECHO reply" (cu type = 0, un ID random si un seq_number care creste
progresiv).
Pentru pachetele de tip ARP, am verificat dupa extragerea header-ului ARP
daca sunt pachete de tip ARP request sau reply (campul "opcode" indica acest
aspect). Daca s-a primit un request, am interschimbat sursa cu destinatia in
header-ul ethernet, iar noua sursa a devenit mac-ul uneia dintre interfetele
router-ului. Daca am primit un reply, am extras adresa mac sursa si am pus-o in
tabela ARP alaturi de adresa ip sursa. Am scos elementul fruntas din coada,
i-am extras header-ul Ethernet, i-am completat adresele sursa si destinatie si
apoi l-am forwardat spre next_hop. Pachetului de reply primit i-am dat drop. 
Pentru pachetele de tip IP nedestinate router-ului: 
	- am verificat ttl-ul sa fie > 1 (daca nu era, am trimis un pachet de tip
time exceeded (cu type = 11) 
	- am verificat ca checksum-ul sa fie corect (ca in laboratorul 4) si am
updatat checksum-ul, am decrementat ttl-ul.  
	- am gasit intrarea potrivita din tabela de routare folosind o functie
auxiliara (daca intrarea era NULL, trimiteam un mesaj de destination
unreachable [type = 3]).
	- am cautat adresa mac corespunzatoare in tabela arp, iar daca intrarea
gasita este NULL, am trimis un arp request. Am facut o copie a pachetului "m"
alocata dinamic pe care am introdus-o intr-o coada de asteptare creata
anterior. 
	- daca am gasit o intrare in tabela Arp nenula, am updatat mac sursa si mac
destinatie, ca apoi sa directionez pachetul spre next_hop-ul aflat. 

-------------------------------------------------------------------------------


