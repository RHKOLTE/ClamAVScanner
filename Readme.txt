Download latest ClamAV windows run time
https://www.clamav.net/downloads/production/clamav-1.4.3.win.x64.zip
Unzip it
into 
E:\Temp\VS
create file 
freshclam.conf with
DatabaseMirror database.clamav.net
DatabaseDirectory E:\Temp\VS\db
UpdateLogFile E:\Temp\VS\freshclam.log
Run the commnad 
cd E:\Temp\VS
freshclam
This will download the latest .cvd file from the server
us the command to unpack the virus defination file.
cd E:\Temp\VS\Unpacked\
E:\Temp\VS\sigtool --unpack E:\Temp\VS\db\main.cvd  
E:\Temp\VS\sigtool --unpack E:\Temp\VS\db\daily.cvd
now we will get the latest 
E:/Temp/VS/Unpacked/main.ndb 
E:/Temp/VS/Unpacked/daily.ndb
Compile the ClamAVScanner.java
javac ClamAVScanner.java 
Run the command to chek if the file had any problme.
java ClamAVScanner E:/Temp/VS/Unpacked/main.ndb E:/Temp/VS/Unpacked/daily.ndb C:/Users/RKolte/Downloads/eicarcom2.zip
