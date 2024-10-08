ip link set dev ens18 promisc on

ip ink show ens18

apt install ethtool
ethtool -k ens18 |grep receive-offload
ethtool -K ens18 gro off lro off
ethtool -k ens18 | grep receive-offload

nano /etc/systemd/system/snort3-nic.service

Contenu du fichier

[Unit] Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
After=network.target

[Service] Type=oneshot
ExecStart=/usr/sbin/ip link set dev ens18 promisc on
ExecStart=/usr/sbin/ethtool -K ens18 gro off lro off
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=default.target

systemctl daemon-reload
systemctl start snort3-nic.service systemctl
enable --now snort3-nic.service

nano /etc/snort/rules/local.rules

Contenu du fichier

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does nots come with signatures. Put your local additions here.

alert icmp any any -> any any (msg:"!!! ICMP Alert !!!";sid:1000001;rev:1;classtype:icmpevent;)

mkdir /var/log/snort
chmod 777 /var/log/snort

nano /etc/snort/snort.lua

Modifier le fichier

    Se rendre tout en bas du fichier, dans la catégorie "7. configure outputs"

---------------------------------------------------------------------------
-- 7. configure outputs
---------------------------------------------------------------------------

alert_fast =
{
    file = true,
    limit = 100000
}

alert_full =
{
    file = true,
    limit = 100000
}

snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -i ens18 -A alert_fast -l /var/log/snort

    Autres options d'alerte :

        alert_fast
        alert_full
        FIN.

![Alt text](pingsnort.png)
