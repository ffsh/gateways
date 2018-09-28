Table of Contents
=================

   * [Infrastruktur](#infrastruktur)
   * [Installation](#installation)
      * [Allgemeine Software Pakete](#allgemeine-software-pakete)
         * [Batman und Fastd](#batman-und-fastd)
            * [Batman Kernel Modul und batctl](#batman-kernel-modul-und-batctl)
            * [fastd](#fastd)
         * [fastd-Konfiguration](#fastd-konfiguration)
         * [Netzwerk Konfiguration](#netzwerk-konfiguration)
            * [IP Forwarding](#ip-forwarding)
            * [Interfaces Konfigurieren](#interfaces-konfigurieren)
            * [IP Tables](#ip-tables)
         * [VPN](#vpn)
            * [VPN-Connect regelmäßig überprüfen](#vpn-connect-regelmäßig-überprüfen)
         * [DHCP](#dhcp)
            * [DHCP isc-dhcp-server IPv4 und IPv6](#dhcp-isc-dhcp-server-ipv4-und-ipv6)
         * [DNS-Server (BIND)](#dns-server-bind)
         * [Mesh Announce](#mesh-announce)
      * [Optional](#optional)
         * [Karte](#karte)
            * [yanic](#yanic)
            * [influxdb](#influxdb)
            * [Grafana](#grafana)
            * [meshviewer](#meshviewer)
               * [nodejs](#nodejs)
               * [yarn](#yarn)
               * [meshviewer-rgb](#meshviewer-rgb)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)


# Infrastruktur

Network IPv4:   10.144.0.0/16
Network IPv6:   fddf:0bf7:80::/48

<table>
  <tr>
    <th>Name</th>
    <th>ULA</th>
    <th>IPv6</th>
    <th>RFC1918</th>
    <th>DHCP</th>
    <th>ICVPN-Transit</th>
    <th>Mesh MAC(s)</th>
    <th>B.A.T.M.A.N.-adv. MAC(s)</th>
    <th>Dienste</th>
    <th>Standort</th>
    <th>Betreuer</th>
    <th>Exit/VPN-Dienst</th>
    <th>Status</th>
  </tr>
  <tr>
    <td>Barnitz<br></td>
    <td>fddf:0bf7:80::48:1</td>
    <td>ULA</td>
    <td>10.144.48.1</td>
    <td>10.144.48.2-10.144.63.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:00:48</td>
    <td>00:5b:27:81:00:48</td>
    <td></td>
    <td>Hetzner (Nbg)</td>
    <td>ul</td>
    <td>Mullvad 3</td>
    <td>online</td>
  </tr>
  <tr>
    <td>Beste</td>
    <td>fddf:0bf7:80::64:1</td>
    <td>ULA</td>
    <td>10.144.64.1</td>
    <td>10.144.64.2-10.144.79.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:00:64</td>
    <td>00:5b:27:81:00:64</td>
    <td></td>
    <td>Hetzner (Fsn)</td>
    <td>ul</td>
    <td>Mullvad 3</td>
    <td>online</td>
  </tr>
  <tr>
    <td>Bille</td>
    <td>fddf:0bf7:80::80:1</td>
    <td>ULA</td>
    <td>10.144.80.1</td>
    <td>10.144.80.2-10.144.95.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:00:80</td>
    <td>00:5b:27:81:00:80</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Brunsbach</td>
    <td>fddf:0bf7:80::96:1</td>
    <td>ULA</td>
    <td>10.144.96.1</td>
    <td>10.144.96.2-10.144.111.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:00:96</td>
    <td>00:5b:27:81:00:96</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Heilsau</td>
    <td>fddf:0bf7:80::112:1</td>
    <td>ULA</td>
    <td>10.144.112.1</td>
    <td>10.144.112.2-10.144.127.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:12</td>
    <td>00:5b:27:81:01:12</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Hopfenbach</td>
    <td>fddf:0bf7:80::128:1</td>
    <td>ULA</td>
    <td>10.144.128.1</td>
    <td>10.144.128.2-10.144.143.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:28</td>
    <td>00:5b:27:81:01:28</td>
    <td>FFSH Karte, FFSH Frimware mirror</td>
    <td>Hetzner</td>
    <td>swo</td>
    <td>PrivateInternetAccess</td>
    <td>online</td>
  </tr>
  <tr>
    <td>Krummbach</td>
    <td>fddf:0bf7:80::144:1</td>
    <td>ULA</td>
    <td>10.144.144.1</td>
    <td>10.144.144.2-10.144.159.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:44</td>
    <td>00:5b:27:81:01:44</td>
    <td>FFSH Frimware mirror</td>
    <td>Hetzner(fsn)</td>
    <td>ks</td>
    <td>direkt</td>
    <td>online</td>
  </tr>
  <tr>
    <td>Piepenbek</td>
    <td>fddf:0bf7:80::160:1</td>
    <td>ULA</td>
    <td>10.144.160.1</td>
    <td>10.144.160.2-10.144.175.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:60</td>
    <td>00:5b:27:81:01:60</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Strusbek</td>
    <td>fddf:0bf7:80::176:1</td>
    <td>ULA</td>
    <td>10.144.176.1</td>
    <td>10.144.176.2-10.144.191.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:76</td>
    <td>00:5b:27:81:01:76</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Sylsbek</td>
    <td>fddf:0bf7:80::192:1</td>
    <td>ULA</td>
    <td>10.144.192.1</td>
    <td>10.144.192.2-10.144.207.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:01:92</td>
    <td>00:5b:27:81:01:92</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>n/a</td>
  </tr>
  <tr>
    <td>Trave</td>
    <td>fddf:0bf7:80::208:1</td>
    <td>ULA</td>
    <td>10.144.208.1</td>
    <td>10.144.208.2-10.144.223.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:02:08</td>
    <td>00:5b:27:81:02:08</td>
    <td></td>
    <td>Hetzner (Fsn)</td>
    <td>ul</td>
    <td>Mullvad 3<br></td>
    <td>online</td>
  </tr>
  <tr>
    <td>Viehbach</td>
    <td>fddf:0bf7:80::224:1</td>
    <td>ULA</td>
    <td>10.144.224.1</td>
    <td>10.144.224.2-10.144.239.254</td>
    <td>n/a</td>
    <td>00:5b:27:80:02:24</td>
    <td>00:5b:27:81:02:24</td>
    <td></td>
    <td>Hetzner(fsn)</td>
    <td>ks</td>
    <td>Mullvad 1 / direkt</td>
    <td>offline</td>
  </tr>
</table>

# Installation

## Allgemeine Software Pakete

Diese Anletugn ist auf Debian 9 ausgerichtet

<pre>
sudo apt install build-essential git apt-transport-https bridge-utils ntp net-tools
</pre>

### Batman und Fastd
Batman Advanced ist das in Stormarn und Lauenburg verwendete Routing Verfahren. Batman Advanced benötigt ein Kernel Modul und batclt.

#### Batman Kernel Modul und batctl
Als <b>root</b> user <code>sudo su</code>:
<pre>
apt install libnl-3-dev libnl-genl-3-dev libcap-dev pkg-config
wget https://downloads.open-mesh.org/batman/releases/batman-adv-2018.0/batman-adv-2018.0.tar.gz
tar xfv batman-adv-2018.0.tar.gz
cd batman-adv-2018.0/
make
make install
</pre>

<pre>
wget https://downloads.open-mesh.org/batman/releases/batman-adv-2018.0/batctl-2018.0.tar.gz
tar xvf batctl-2018.0.tar.gz
cd batctl-2018.0/
make
make install
</pre>

In <code>/etc/modules</code> folgenden Eintrag ergänzen.
<pre>
batman-adv
</pre>

#### fastd
fastd v18 ist in Debian 9 bereits in den Repositorys enthalten. Unter Debian 8 findet man es in den jessie-backports.

<pre>
sudo apt install fastd
</pre>

### fastd-Konfiguration
Wir brauchen für den neuen Server die Schlüssel für fastd. Diese sind in Stormarn für 12 Gateways bereits in der Firmware eingetragen und den privaten Schlüssel gibt es über Kaj.

Im Folgenden wird der sichere private Schlüssel als [SERVER-SECRET-KEY] aufgeführt und müssen durch die erzeugten Schlüssel sinnvoll ersetzt werden!

Bitte als root zwei neue Verzeichnisse anlegen. Dort werden die Schlüssel für das Freifunknetz hinterlegt, damit Gateway und Router später zusammenfinden können:
<pre>
mkdir /ffsh
mkdir /ffsh/gateway/peers
mkdir /ffsh/gateway/gateways
</pre>

Es ist eine Konfigurationsdatei für fastd notwendig. In der folgenden Konfiguration bitte die [EXTERNE-IPv4] durch die echte IP vom Server ersetzen. Wenn es auch eine IPv6 gibt, kann die entsprechende Zeile aktiviert werden und benötigt die echte IPv6 [EXTERNE-IPv6].
Die Konfigurationsdatei <code>/etc/fastd/ffsh/fastd.conf</code> soll bitte diese Zeilen enthalten:

<pre>
# Bind to a fixed address and port, IPv4 and IPv6 at Port 1234
bind any:10000 interface "eth0";
# bind [EXTERNE-IPv6]:1234 interface "eth0";

# Set the user, fastd will work as
user "ffsh";

# Set the interface name
interface "ffsh-mesh";

# Set the mode, the interface will work as
mode tap;

# Set the mtu of the interface (salsa2012 with ipv6 will need 1406)
mtu 1426;

# Set the methods (aes128-gcm preferred, salsa2012+umac preferred for nodes)
method "salsa2012+umac";
method "null";  # NUR WENN DAS GW UNVERSCHLÜSSELT ANNEHMEN DARF, Knoten Betreiber in Stormarn und Lauenburg haben die Wahl ob sie Verschlüsseln wollen oder nicht.

#hide ip addresses yes;
#hide mac addresses yes:

# Secret key generated by `fastd --generate-key`
secret "[SERVER-SECRET-KEY]";

# Log everything to syslog
log to syslog level debug;

# Include peers from our git-repos
#include peers from "peers/"; #optional eigene peers anlegen zb den eigenen toaster mit fastd oder so
include peers from "gateways/"; #git repo klonen in /etc/fastd/ffsh/ git clone  https://github.com/ffsh/gateways.git

# Configure a shell command that is run on connection attempts by unknown peers (true means, all attempts are accepted)
on verify "true";
# on verify "/etc/fastd/fastd-blacklist.sh $PEER_KEY";

# Configure a shell command that is run when fastd comes up
on up "
 ip link set dev $INTERFACE address 00:5b:27:80:0X:XX           # X für das GW Netz, zB 2:24 für 10.144.224.0/20
 ip link set dev $INTERFACE up
 ifup bat0
 sh /etc/fastd/ffod/iptables_ffod.sh
";
</pre>

Das Beste ist, wenn man nun die fastd-Konfiguration mal überprüft. Vorher muss der Server rebootet werden, damit die vorher durchgeführten Anpassungen auch Wirkung zeigen :-)

Dann als root auf der Konsole mit folgender Zeile die fastd Einstellungen prüfen:

<pre>
fastd -c /etc/fastd/ffsh/fastd.conf
</pre>

Wenn das erfolgreich war, kann nun fastd gestartet werden, auch wieder als root mit:

<pre>
systemctl start fastd
</pre>

Wichtig:
In der Konfiguration wird jeder Router reingelassen. Das mag nicht jeder, aber es vereinfacht die Integration der Router und damit auch die Verteilung. Wenn man das nicht möchte, müsste jeder Router separat mit seinem öffentlichen Schlüssel unter <code>.../peers/</code> hinterlegt werden. Auskommentiert ist eine Zeile bei <code>on verify</code> die eine Blacklist führt. Damit kann man unliebsame Genossen aussperren. Wenn man das haben möchte, so ist eine Datei <code>/etc/fastd/fastd-blacklist.sh</code> zu erstellen mit folgenden Zeilen und dann auch ausführbar zu machen:

<pre>
#!/bin/bash
PEER_KEY=$1
if /bin/grep -Fq $PEER_KEY /etc/fastd/fastd-blacklist.json; then
    exit 1
else
    exit 0
fi
</pre>

Wie die weiteren Dateien mit der Blacklist aussehen, findet man unter diesem Link https://github.com/ffruhr/fastdbl

### Netzwerk Konfiguration

#### IP Forwarding
In der Konfigurationsdatei <code>/etc/sysctl.d/forwarding.conf</code> bitte die folgenden Zeilen eintragen, damit das IP Forwarding für IPv4 und IPv6 laufen:
<pre>
# IPv4 Forwarding
net.ipv4.ip_forward=1

# IPv6 Forwarding
net.ipv6.conf.all.forwarding = 1
</pre>

#### Interfaces Konfigurieren
Nun kommt das eigentlich wichtigste. Das Netzwerk muss eingerichtet werden, so das die einzelnen Schnittstelle bereitstehen und eine Art Brücke vom Freifunknetz in das Internet aufbauen.

Als erstes kommt die Netzwerkbrücke (Schnittstelle zwischen dem "Mesh" Netzwerk und dem Internet-Ausgang per VPN:

Hinweis: diese Konfiguration ist allgemeingültig für unser Netz. Daher ist das jeweilige Gateway in den IP-Adressen mit [GW Nr] geschrieben. Diese Nummer muss natürlich durchgänig gleich sein, da sonst nichts funktionieren wird!

Bitte die <code>/etc/network/interfaces</code> mit Folgenden Zeilen befüllen. Das eth0 sollte so belassen werden, wie es bereits eingerichtet war, damit die Netzwerkhardware auch weiterhin im Internet erreichbar ist:
<pre>
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface (here it's a local network)
allow-hotplug eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.224
    network 192.168.1.0
    gateway 192.168.1.1
    dns-nameservers 10.144.0.1 85.214.20.141 213.73.91.35

# Netwerkbruecke fuer Freifunk
# - Hier laeuft der Traffic von den einzelnen Routern und dem externen VPN zusammen
# - Unter der hier konfigurierten IP ist der Server selber im Freifunk Netz erreichbar
# - bridge_ports none sorgt dafuer, dass die Bruecke auch ohne Interface erstellt wird

auto br-ffod
iface br-ffod inet static
    address 10.144.[GW Netz].1
    netmask 255.255.0.0
    bridge_ports none

iface br-ffod inet6 static
    address fddf:0bf7:80::[GW Netz]:1
    netmask 64

    post-up /sbin/ip -6 addr add fddf:0bf7:80::[GW Netz]:1/64 dev br-ffod
    post-up /sbin/ip rule add iif br-ffod table 42
    pre-down /sbin/ip -6 addr del fddf:0bf7:80::[GW Netz]:1/64 dev br-ffod
    pre-down /sbin/ip rule del iif br-ffod table 42

# Batman Interface
# - Erstellt das virtuelle Inteface fuer das Batman-Modul und bindet dieses an die Netzwerkbruecke
# - Die unten angelegte Routing-Tabelle wird spaeter fuer das Routing innerhalb von Freifunk (Router/VPN) verwendet
#
# Nachdem das Interface gestartet ist, wird eine IP-Regel angelegt, die besagt, dass alle Pakete, die über das bat0-Interface eingehen,
# und mit 0x1 markiert sind, über die Routing-Tabelle 42 geleitet werden.
# Dies ist wichtig, damit die Pakete aus dem Mesh wirklich über das VPN raus gehen.
#

allow-hotplug bat0
iface bat0 inet6 manual
    pre-up batctl if add ffod-mesh
    post-up ip link set address 00:5b:27:81:0[GW Netz] dev bat0   # ACHTUNG BEI GW NETZ DEN DOPPELPUNKT NICHT VERGESSEN (80=0:80 128=1:28)
    post-up ip link set dev bat0 up # Notwendig?
    post-up brctl addif br-ffod bat0
    post-up batctl it 10000
    post-up batctl gw server 100 Mbit/ 100 Mbit

    post-up ip rule add from all fwmark 0x1 table 42

    pre-down brctl delif br-ffod bat0 || true
    down ip link set dev bat0 down


</pre>

Die <code>/etc/hosts</code> mit Folgenden Zeilen befüllen:

<pre>
127.0.0.1                  localhost
[externe IP]               [GW Name].ffod.org   [GW Name]
10.144.[GW Netz].1         ffod
fddf:0bf7:80::[GW Netz]:1  ffod
</pre>

#### IP Tables
Lege die Konfigurationsdatei <code>/etc/iptables.up.rules</code> an mit Folgendem:

Damit werden alle Pakete, die über die Bridge rein kommen, mit dem 0x1-Flag markiert, und damit über Routing-Tabelle 42 geschickt.
Es gibt noch 2 Regeln für DNS, dass auch DNS-Pakete (Port 53 TCP/UDP) über die Tabelle 42 geschickt werden.
<pre>
  *filter
  :INPUT ACCEPT [0:0]
  :FORWARD ACCEPT [0:0]
  :OUTPUT ACCEPT [0:0]
  COMMIT
  *mangle
  :PREROUTING ACCEPT [0:0]
  :INPUT ACCEPT [0:0]
  :FORWARD ACCEPT [0:0]
  :OUTPUT ACCEPT [0:0]
  :POSTROUTING ACCEPT [0:0]
  COMMIT
  *nat
  :PREROUTING ACCEPT [0:0]
  :INPUT ACCEPT [0:0]
  :OUTPUT ACCEPT [0:0]
  :POSTROUTING ACCEPT [0:0]
  COMMIT
</pre>

Nun müssen die IP Tables geladen werden.
Bitte erstellt die Datei <code>/etc/network/if-pre-up.d/iptables</code> mit folgenden Zeilen:
<pre>
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.up.rules
</pre>

Bitte nun noch eine Datei <code>/etc/fastd/ffod/iptables_ffod.sh</code> erstellen, die alle Routing <code>iptables</code> Vorgaben enthält:
<pre>
#!/bin/sh
/sbin/ip route add default via [EXTERNE-IPv4] table 42
/sbin/ip route add 10.144.0.0/16 dev br-ffod src 10.144.[GW Netz].1 table 42
/sbin/ip route add 0/1 dev tun0 table 42
/sbin/ip route add 128/1 dev tun0 table 42
/sbin/ip route del default via [EXTERNE-IPv4] table 42
/sbin/iptables -t nat -D POSTROUTING -s 0/0 -d 0/0 -j MASQUERADE > /dev/null 2>&1
/sbin/iptables -t nat -I POSTROUTING -s 0/0 -d 0/0 -j MASQUERADE
/sbin/iptables -t nat -D POSTROUTING -s 0/0 -d 0/0 -o tun0 -j MASQUERADE > /dev/null 2>&1
/sbin/iptables -t mangle -D PREROUTING -s 10.144.[GW Netz].0/20 -j MARK --set-mark 0x1 > /dev/null 2>&1
/sbin/iptables -t mangle -I PREROUTING -s 10.144.[GW Netz].0/20 -j MARK --set-mark 0x1
/sbin/iptables -t mangle -D OUTPUT -s 10.144.[GW Netz].0/20 -j MARK --set-mark 0x1 > /dev/null 2>&1
/sbin/iptables -t mangle -I OUTPUT -s 10.144.[GW Netz].0/20 -j MARK --set-mark 0x1
</pre>
Jetzt müssen die für Linux ausführbar werden. Dazu dies als root auf der Konsole eingeben:

<pre>
chmod +x /etc/network/if-pre-up.d/iptables
chmod +x /etc/fastd/ffod/iptables_ffod.sh

iptables-restore < /etc/iptables.up.rules
</pre>

### VPN
Achtung:
Kopiere bitte nicht die Konfigurationsdateien von einem Gateway auf andere Gateways!

Für das VPN werden diese Dateien benötigt, die alle nach <code>/etc/openvpn/</code> müssen:
<pre>
ca.crt
crl.pem
mullvad.crt
mullvad.key
mullvad_linux.conf
</pre>

Die Datei <code>mullvad_linux.conf</code> muss noch um folgende Zeilen am Ende ergänzt werden:

<pre>
#custom
route-noexec
up /etc/openvpn/mullvad_up.sh
up /etc/fastd/ffod/iptables_ffod.sh
</pre>
Mullvad hat an seinen Konfigurationen seit mehreren Sicherheitslücken bei OpenVPN und Snowden/NSA geändert. Es kann sein, dass ein Fehler zur Cipher-Liste angezeigt wird. Dann muss in der <code>mullvad_linux.conf</code> die Zeile zur TLS-Verschlüsselung beginnend <code>tls-cipher</code> auskommentiert werden. Wenn kein <code>IPv6</code> am Server ins Internet möglich ist, kann auch <code>tun-ipv6</code> auskommentiert werden.


Die Datei <code>/etc/openvpn/mullvad_up.sh</code> gibt es noch nicht.Also bitte die Datei mit folgenden Zeilen anlegen:
<pre>
#!/bin/sh
ip route replace 0.0.0.0/1 via $5 table 42
ip route replace 128.0.0.0/1 via $5 table 42

service dnsmaq restart
exit 0
</pre>
Diese Datei muss nun auch als root ausführbar gemacht werden:

<code>chmod +x /etc/openvpn/mullvad_up.sh</code>

Damit Linux auch diese VPN-Schnittstelle kennt, muss <code>tun</code> in der Datei <code>/etc/modules</code> bekannt gemacht werden. OpenVPN benötigt ein tun-Interface.
Trage einfach in eine eigene neue Zeile dies ein

<pre>
tun
</pre>

Bitte nun als root über die Konsole tun aktivieren und den VPN starten mit:

<pre>
modprobe tun
service openvpn start
</pre>

#### VPN-Connect regelmäßig überprüfen
Es ist sinnvoll regelmäßig zu prüfen, ob die VPN Verbindung noch aktiv ist. Dazu wird ein Script auf dem Server abgelegt, dass dann über den CRON immer neu den VPN-Connect prüft.

Script <code>/ffod/check-vpn.sh</code>
<pre>
#!/bin/bash

# Test gateway is connected to VPN
test=$(ping -q -I tun0 8.8.8.8 -c 4 -i 1 -W 5 | grep 100 )

if [ "$test" != "" ]
    then
    echo "VPN nicht da - Neustart!"
    service openvpn restart      # Fehler - VPN nicht da - Neustart
else
    echo "alles gut"
fi
</pre>

Dann noch das Script ausführbar machen:

<pre>
chmod ug+x /ffod/check-vpn.sh
</pre>

Danach in die Datei <code>/etc/crontab</code> das Skript alle 10 Minute auszuführen und damit regelmäßig der VPN-Status geprüft wird.
<pre>
# Check VPN via openvpn is running, if not service restart
*/10 * * * * root /ffod/check-vpn.sh > /dev/null
</pre>
Die Änderungen übernehmen durch einen Neustart des Cron-Dämonen:
<pre>
service cron restart
</pre>


### DHCP

<pre>
apt install radvd isc-dhcp-server
</pre>

#### DHCP radvd IPv6

Es wird für IPv6 die Konfigurationsdatei <code>/etc/radvd.conf</code> mit folgenden Zeilen benötigt:
<pre>
interface br-ffod {
    AdvSendAdvert on;
    IgnoreIfMissing on;
    AdvManagedFlag off;
    AdvOtherConfigFlag on;
    MaxRtrAdvInterval 200;
    AdvLinkMTU 1280;
    prefix fddf:0bf7:80::/64 {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };

    RDNSS fddf:0bf7:80::[GW Netz]:1 {
    };
};
</pre>


Jetzt kann <code>radvd</code> als root auf der Konsole gestartet werden:
<pre>
service radvd restart
</pre>

#### DHCP isc-dhcp-server IPv4 und IPv6
Die Konfigurationsdatei <code>/etc/dhcp/dhcpd.conf</code> wird für IPv4 mit folgenden Zeilen benötigt:
<pre>
ddns-update-style none;
option domain-name ".ffod";

# möglichst kurze Leasetime
default-lease-time 120;
max-lease-time 600;

log-facility local7;

subnet 10.144.0.0 netmask 255.255.0.0 {
    authoritative;
    range 10.144.[GW Netz].2 10.144.[GW Netz + 15].254;

    option routers 10.144.[GW Netz].1;

    option domain-name-servers 10.144.[GW Netz].1; # für die eigenen DNS-Einträge
    # option domain-name-servers 85.214.20.141; # weitere anonyme DNS
    # option domain-name-servers 213.73.91.35;
}

include "/etc/dhcp/static.conf";
</pre>

Bitte eine leere Datei <code>/etc/dhcp/static.conf</code> erzeugen.

```
useradd -m -s /bin/bash dhcpstatic

cd /home/dhcpstatic

su dhcpstatic

git clone https://github.com/ffsh/dhcp-static.git

chmod +x dhcp-static/updateStatics.sh

exit

/home/dhcpstatic/dhcp-static/updateStatics.sh

*/5 * * * * root /home/dhcpstatic/dhcp-static/updateStatics.sh > /dev/null 2>&1
```


Auf dem DHCP-Server muss noch das Bridge-Interface für IPv4 festgelegt werden. Bitte die Datei <code>/etc/default/isc-dhcp-server</code> mit folgender Option ergänzen:
<pre>
# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
# Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACES="br-ffod"
</pre>

Am Besten wird der DHCP-Server vor dem Start und Betrieb noch mal geprüft. Bitte vorher den Server rebooten und dann auf der Konsole als root folgende Zeile ausführen:

<pre>
dhcpd -f -d
</pre>

War das erfolgreich, so kann der DHCP-Server als root gestartet werden:

<pre>
systemctl restart isc-dhcp-server
</pre>

### DNS-Server (BIND)
<pre>
apt install bind9
</pre>

Für das interne Freifunknetz ist nun noch der DNS-Server <code>bind9</code> mit den Konfigurationsdateien wie folgt zu konfigurieren:

Erstmal diese Datei <code>/etc/bind/named.conf.options</code>

<pre>
options {
    directory "/var/cache/bind";
    // If there is a firewall between you and nameservers you want
    // to talk to, you may need to fix the firewall to allow multiple
    // ports to talk.  See http://www.kb.cert.org/vuls/id/800113
    // If your ISP provided one or more IP addresses for stable
    // nameservers, you probably want to use them as forwarders.
    // Uncomment the following block, and insert the addresses replacing
    // the all-0's placeholder.
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
    //========================================================================
    // If BIND logs error messages about the root key being expired,
    // you will need to update your keys.  See https://www.isc.org/bind-keys
    //========================================================================
    // dnssec-enable yes;
    // dnssec-validation yes;
    dnssec-validation no;
    // dnssec-lookaside auto;
    // recursion yes;
    // allow-recursion { localnets; localhost; };
    auth-nxdomain no;    # conform to RFC1035
    listen-on-v6 { any; };
};
</pre>

Dann in der Datei <code>/etc/bind/named.conf.local</code> folgendes am Ende ergänzen:
<pre>
// Do any local configuration here
// Consider adding the 1918 zones here, if they are not used in your organization

include "/etc/bind/zones.rfc1918";

zone "stormarn.freifunk.net" {
       type master;
       file "/etc/bind/db.net.freifunk.stormarn";
  };

zone "freifunk-stormarn.de" {
       type master;
       file "/etc/bind/db.de.freifunk-stormarn";
  };

zone "lauenburg.freifunk.net" {
       type master;
       file "/etc/bind/db.net.freifunk.lauenburg";
  };

zone "freifunk-lauenburg.de" {
       type master;
       file "/etc/bind/db.de.freifunk-lauenburg";
  };

zone "freifunk-suedholstein.de" {
        type master;
        file "/etc/bind/db.de.freifunk-suedholstein";
};

zone "ffshev.de" {
     type master;
     file "/etc/bind/db.de.ffshev";
};

</pre>

Nun die <code>db.net.freifunk.stormarn</code> Datei mit Inhalt füllen:
Dazu https://github.com/ffod/bind TODO

Achtung, je nach Einstellungen bitte auch die resolv.conf beachten, damit später auch DNS funktioniert!!!

Mit den Dateien kann <code>bind9</code> als root über die Konsole gestartet werden:

<pre>
service bind9 restart
</pre>

### Mesh Announce
Um als Gateway, Server oder alles was kein Freifunk Router ist auf der Karte zu erscheinen kann [mesh-announce](https://github.com/ffnord/mesh-announce) installiert werden.

Dafür müssen folgende Dinge vorhanden sein:
<pre>
lsb_release, ethtool, python3 (>= 3.3)
sudo apt install ethtool python3
</pre>

Mesh Announce kann auch im alfred Stil Daten broadcasten das wollen wir aber nicht.

<pre>
sudo git clone https://github.com/ffnord/mesh-announce /opt/mesh-announce
sudo cp /opt/mesh-announce/respondd.service /etc/systemd/system/respondd.service
nano /etc/systemd/system/respondd.service
</pre>
Und an das System anpassen:
<pre>
your-clientbridge-if - br-ffrz | br-ffod
your-mesh-vpn-if     - ffrz-mesh | ffod-mesh
your-batman-if       - ffrz-mesh | ffod-mesh # Damit die MAC oben aus der Tabelle benutzt wird
</pre>
<pre>
[Unit]
Description=Respondd

[Service]
ExecStart=/opt/mesh-announce/respondd.py -d /opt/mesh-announce -i br-ffrz -i ffrz-mesh -b ffrz-mesh
Restart=always
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
</pre>

Dann mit <code>hostname</code> prüfen ob der erwünschte Gateway-Name eingetragen ist ggf. ändern oder:

<code>/opt/mesh-announce/nodeinfo.d/hostname</code>
<pre>
#import_module('socket').gethostname()
"GW_Hopfenbach"
</pre>
Dann den Service aktivieren
<pre>
systemctl daemon-reload
systemctl start respondd
# autostart on boot
systemctl enable respondd
</pre>
Das System sollte in kürze auf der Karte auftauchen.

## Optional

Die Folgenden Schritte dienen dazu, eine Karte anzuzeigen. Dies lässt sich auch auf einem vom Gateway getrennten System durchführen.
### Karte

[[Datei:map-uebersicht.png]]

#### yanic
[yanic](https://github.com/FreifunkBremen/yanic) sammelt von den Knoten Daten, welche dann auf einer Karte angezeigt werden können, früher wurde hierfür Alfred benutzt.
yanic ist in go geschrieben also installieren wir eine neue Version von go.
[golang](https://golang.org/dl/)

<pre>
wget https://dl.google.com/go/go1.10.1.linux-amd64.tar.gz
# Bitte sha256 vergleichen
tar -C /usr/local -xzf go1.10.1.linux-amd64.tar.gz
rm go1.10.1.linux-amd64.tar.gz
</pre>

<pre>
sudo su
</pre>

Als root in <code>~/.bashrc</code>

<pre>
GOPATH=/opt/go
PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
</pre>

Mit <code>whereis go</code> prüfen ob go gefunden wird:

<pre>
go: /usr/local/go /usr/local/go/bin/go
</pre>

Dann wird yanic installiert.

<pre>
go get -v -u github.com/FreifunkBremen/yanic
</pre>

Die Konfiguration von Yanic wird in <code>/etc/yanic.conf</code> angelegt

<pre>
https://raw.githubusercontent.com/ffsh/ffshConfigs/master/yanic.conf
</pre>

Wir können testen ob yanic funktioniert in dem wir eine manuelle Anfrage stellen hier an das Gateway Hopfenbach:

TODO Service anlegen

<pre>
yanic query --wait 5 bat0 "fddf:0bf7:80::128:1"
</pre>

#### influxdb
Influxdb dient als Datenbank für yanic
<pre>
sudo apt install influxdb influxdb-client
</pre>

Nun sichern wir die influxdb ab <code>/etc/influxdb/influxdb.conf</code>

Hier werden nur die empfohlenen Anpassungen beschrieben:
Noch vor der <code>[meta]</code> Sektion setzen wir, sonst wäre der port 8088 überall offen.
<pre>
bind-address = "localhost:8088"
</pre>

Weiter unten bei <code>[admin]</code> das gleiche:

<pre>
bind-address = "localhost:8083"
</pre>

kurz danach in <code>[http]</code>

<pre>
bind-address = "localhost:8086"
</pre>

<code>systemctl restart influxdb</code>

Nun sollte influxdb nur noch auf localhost erreichbar sein, prüfen kann man dies mit
<code>netstat -tlpn</code>

#### Grafana
Grafana kann Graphen erstellen welche im meshviewer eingebunden werden können.
Hier wird [Grafana](http://docs.grafana.org/installation/debian/) über eine Repository installiert.
<pre>
deb https://packagecloud.io/grafana/stable/debian/ stretch main
curl https://packagecloud.io/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install grafana
</pre>

TODO sichere Konfiguration

#### meshviewer
Für den Meshviewer installieren wir als erstes nodejs und yarn

##### nodejs
Wir brauchen ein aktuelles nodejs das finden wir auf [nodejs.org](https://nodejs.org/en/download/package-manager/)
Wir benutzen die LTS Variante 8.x
<pre>
curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
sudo apt-get install -y nodejs
</pre>

##### yarn
Dann installieren wir [yarn](https://yarnpkg.com/en/docs/install#linux-tab)
<pre>
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
</pre>

##### meshviewer-rgb
Nun installieren wir den [meshviewer](https://doc.meshviewer.org/) selbst.
Im web Verzeichnis <code>/var/www/</code>
<pre>
git clone https://github.com/ffsh/meshviewer.git
cd meshviewer
yarn
</pre>

Nun muss die Konfiguration in <code>meshviewer/config.js</code> eventuell noch angepasst werden.

Danach <code>yarn run gulp</code> Nun muss nur noch ein Webserver <code>meshviewer/build</code> ausliefern.
