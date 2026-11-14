# **E-Commerce Server Doomsday Plan on Rocky Linux**

1. Make sure we are on the right system

hostname  
ip \-br addr  
id

2. Change passwords of all accounts (especially admins)

passwd  
sudo passwd root  
sudo passwd ecomuser

3. Audit users and admins, list every account (watch ones ending in /bin/bash), see who has sudo. Remove or lock anything we dont recognize

cat /etc/passwd  
getent group wheel  
sudo gpasswd \-d \<user\> wheel  
sudo usermod \-L \<user\>  
sudo ls /etc/sudoers.d/

4. Kill persistence: Check cron jobs, systemd times, and services set to start on boot. Remove anything suspicious. 

sudo crontab \-l  
crontab \-l  
ls /etc/cron.d /etc/cron.daily /etc/cron.hourly  
sudo systemctl list-timers  
sudo systemctl list-unit-files \--state=enabled  
sudo systemctl disable \--now \<service\>

5. Firewall: check status, turn it on, see what is open, allow only what is needed, then reload.

sudo firewall-cmd \--state  
sudo systemctl enable \--now firewalld  
sudo firewall-cmd \--list-all  
sudo firewall-cmd \--permanent \--add-service=http  
sudo firewall-cmd \--permanent \--add-service=https  
sudo firewall-cmd \--permanent \--remove-service=\<svc\>  
sudo firewall-cmd \--reload

6. Web server (Apache): Confirm the storefront is up, see what’s listening, check recent errors:

systemctl status httpd  
sudo ss \-tulpn  
sudo systemctl restart httpd  
sudo tail /var/log/httpd/error\_log

7. Database (MariaDB): confirm it’s up, re-run the lockdown, then list DB accounts and watch for unexpected ones

systemctl status mariadb  
sudo mysql\_secure\_installation  
sudo mysql \-u root \-p  
SELECT user,host FROM mysql.user;

8. Patch and watch: update packages (check comp rules), see who is logged in, confirm the storefront still responds.

sudo dnf update \-y  
who  
last  
curl http\://localhost

