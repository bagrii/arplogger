# ARPLogger
Intercept ARP packets on specified network interface and log all activity.

## Build
- Install latest version of [Go](https://go.dev/doc/install).
- Run: `go build main.go -o arplogger` in the root folder.
- Install *(optional)*: `go install .`

## Usage
The following command line flags are available:

`-interface` Network interface to listen ARP packets.  
`-log` Store all ARP activity to log file.  
`-console` Print to console.  
`-all` Dump all ARP packets.  
`-new` Dump only new mapping of IP <-> MAC.

## Examples

Listen on network interface "en0" and print to console only new pairs of IP <-> MAC:  

`arplogger -interface en0 -console -new`

Listen on network interface "en0" and print to console and save to log file, only new pairs of IP <-> MAC:  

`arplogger -interface en0 -console -log -new`

Listen on network interface "en0" and print to console all incoming ARP packets:

`arplogger -interface en0 -console -log -all`

Listen on network interface "en0" and print to console and log file all incoming ARP packets. Additionally, display new mapping of IP <-> MAC:

`arplogger -interface en0 -console -log -all -new`
