# smbcli: a simple test program for jcifs-ng
smbcli is a simple test program aiming at simply debugging [jcifs-ng](https://github.com/AgNO3/jcifs-ng) to get [nova video player](https://github.com/nova-video-player/aos-AVP) working with SMBv2/3.
It only does a file listing of a SMB network share directory.

## Compilation
Project can be run directly via IntelliJ IDE but one can compile it via these commands if you prefer CLI:
```
rm -rt target
mvn package -DskipTests -Dmaven.javadoc.skip=true
```
## Usage
`java -jar jcifstest-1.0-SNAPSHOT.jar 1|2 BCAST|DNS smb://server/share/ [domain user password]`

For guest login (unprotected shares) just omit `"" user password` as domain user password.

## Logs
To get trace logs for jcifs-ng use the following `log4j.properties` file in the root directory where smbcli is run. Sample file is provided in the project.

## pcap capture
For pcap captures, use wireshark with the following filter `ip.src == 192.168.0.101/24 && ip.dst == 192.168.0.1/24` (adapt to your subnet).
To export capture: edit mark all displayed, file export specified packets -> pcap, zip export.

Alternatively tcpdump can be used too with the following command: `sudo tcpdump -n "src net 192.168.1.0/24 and dst net 192.168.1.0/24" -w capture.pcap`

## Recompile jcifs-ng
In order to compile jcifs-ng use maven: `mvn package -DskipTests -Dmaven.javadoc.skip=true`, resulting jar is located in target directory.

To get trace log for jcifs-ng use the following log4j.properties file in the directory where smbcli is present:
