Download latest ClamAV windows run time
https://www.clamav.net/downloads/production/clamav-1.4.3.win.x64.zip
Unzip it
into 
E:\Temp\ClamAVScanner\ClamAV\clamav-1.4.3.win.x64

Create file 
freshclam.conf with
DatabaseMirror database.clamav.net
DatabaseDirectory E:\Temp\ClamAVScanner\db
UpdateLogFile E:\Temp\ClamAVScanner\db\freshclam.log

Run the commnad 
cd E:\Temp\ClamAVScanner\ClamAV\clamav-1.4.3.win.x64
freshclam
This will download the latest .cvd file from the server
us the command to unpack the virus defination file.
cd E:\Temp\ClamAVScanner\db
E:\Temp\ClamAVScanner\ClamAV\clamav-1.4.3.win.x64\sigtool --unpack E:\Temp\ClamAVScanner\db\main.cvd  
E:\Temp\ClamAVScanner\ClamAV\clamav-1.4.3.win.x64\sigtool --unpack E:\Temp\ClamAVScanner\db\daily.cvd
now we will get the latest 
E:\Temp\ClamAVScanner\db\main.ndb 
E:\Temp\ClamAVScanner\db\daily.ndb

Compile the ClamAVScanner.java
cd E:\Temp\ClamAVScanner
javac ClamAVScanner.java 

Run the command to chek if the file had any problme.
java ClamAVScanner db\main.ndb db\daily.ndb testfile\eicarcom2.zip
