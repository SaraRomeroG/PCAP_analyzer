# Guia d'usuari per a l'eina d'anàlisi de fitxers PCAP

Aquesta guia d'usuari proporciona instruccions detallades per utilitzar l'eina desenvolupada per analitzar fitxers PCAP i detectar comportaments maliciosos a la xarxa. El sistema està dissenyat per ser accessible per usuaris amb coneixements limitats en ciberseguretat o programació, utilitzant una interfície de línia de comandes (CLI).

## Requisits previs

- Python 3.11 o una versió superior.
- Les següents biblioteques instal·lades: `Pyshark`, `Pandas`, `MaxMind GeoIP2`. Es poden instal·lar amb la següent comanda:
  ```bash
  pip install -r requirements.txt
- Fitxer GeoLite2-City.mmdb descarregat des de MaxMind: [Descarregar GeoLite2-City.mmdb
](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

## Passos per a utilitzar el sistema
1. Preparació de l'entorn
   
- Instal·lar Python i les biblioteques necessàries.
- Obtenir un fitxer PCAP per analitzar.
   
2. Carregar un fitxer PCAP
Un cop es té el fitxer PCAP, es pot començar a analitzar-lo. Per veure les accions possibles, utilitzeu la següent comanda:
```bash
python analisi_pcap.py camí_del_fitxer.pcap -h

3. Selecció de l'anàlisi a realitzar
El sistema permet escollir entre els següents tipus d'anàlisi:

  - syn: Detecta possibles SYN Scan.

  - fin: Detecta possibles FIN Scan.

  - xmas: Detecta possibles Xmas scan.

  - null: Detecta possibles null scan.

  - ddos: Detecta possibles DDoS.

  - dns: Retorna el nombre de sol·licituds DNS fetes per IP, els dominis més sol·licitats, IPs que accedeixen a dominis maliciosos, IPs que accedeixen a dominis amb TLDs inusuals i detecta possibles túnels DNS.

  - icmp: Analitza el trànsit ICMP i detecta anomalies com Ping Floods i IPs que pinguegen múltiples destinacions.

  - http: Analitza les sessions HTTP i detecta activitat sospitosa com exfiltració de dades.

  - lat-movement: Detecta moviments laterals dins de la xarxa interna.

  - find-ip: Cerca totes les coincidències per una IP determinada a la xarxa.

  - find-ip-country: Cerca les IPs que provenen d'un país específic utilitzant geolocalització. Si no s'especifica cap país, es mostren les estadístiques generals de tràfic.

  - stats: Genera estadístiques bàsiques sobre el trànsit de xarxa (protocols, IPs, ports més utilitzats).

  - geo-ips: Geolocalitza les IPs úniques trobades en el fitxer PCAP.

  - list-ips: Llista totes les IPs úniques de la xarxa.

  - protocols: Llista els protocols detectats en el fitxer PCAP.

  - sessions: Mostra les sessions més freqüents entre IPs.

  - timeline: Genera la línia de temps del trànsit de xarxa basat en el fitxer PCAP. Si es dona una data com a paràmetre amb el format YYYY-MM-DD, es mostra la línia de temps d'aquella data. Si es donen dues dates amb el format YYYY-MM-DD:YYYY-MM-DD, es mostra la línia de temps entre aquelles dates. Si no es dona cap data, es mostra la línia de temps de tot l'arxiu PCAP.

  - top-macs: Llista les 10 primeres adreces MAC per origen i destinació.

  - compare: Compara dos fitxers PCAP per analitzar les diferències en IPs i protocols.

  - domains: Extrau tots els dominis DNS consultats durant l'anàlisi.

  - access-domain: Mostra les IPs que han accedit a un domini específic.

  - list-ports: Llista els ports més utilitzats per les connexions de xarxa.

  - ip-count: Llista el nombre total de paquets enviats i rebuts per cada IP.

  - session-detail: Detalla les sessions entre dues IPs específiques.

  - dns-to-ip: Mostra totes les IPs resoltes per un domini DNS determinat.

  - loc-ip: Localitza completament una IP especificada (geolocalització).

4. Exemple d'ús
Per exemple, per realitzar una detecció de SYN Scan, utilitzeu la següent comanda:
```bash
python analitzarPCAP.py fitxer.pcap syn
