rm httpd_81*
rm libmonitor.so
rm monitor.conf
IP=192.168.0.147
wget http://$IP:8000/httpd_81
wget http://$IP:8000/httpd_81_patch
wget http://$IP:8000/monitor.conf
wget http://$IP:8000/libmonitor.so.arm_uclibc -O libmonitor.so
wget http://$IP:8000/process_monitor.arm_uclibc -O process_monitor
chmod +x httpd_81*
chmod +x process_monitor

echo "./process_monitor ./httpd_81_patch" > run.sh
chmod +x run.sh