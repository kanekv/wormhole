SSH remote port forwarder
=========================

This proxy lets you forward remote port on a machine 
that doesn't have access to public internet.
Imagine you have 3 machines: A, B and C. You want to access port
80 on the machine A from machine C. A and C can't access each other,
but they both can access B. This ssh proxy will be ran on machine B and 
let you forward port from machine A to some port on machine C.

Install
-------

```
go get github.com/Kane-Sendgrid/wormhole
```

Usage
-----

### run on machine B
```bash
export WORMHOLE_PRIVATEKEYPATH=./id_rsa # path to proxy(host) private key on machine B
export WORMHOLE_LOCALSSHADDR=0.0.0.0:2022 # proxy listen address on machine B
export WORMHOLE_REMOTESSHADDR=machineC.com:22 # target ssh address (machine C) 
export WORMHOLE_REMOTESSHUSER=ubuntu # user to authenticate on machine C
export WORMHOLE_REMOTEPRIVATEKEYPATH=./key.pem # private key to authenticate on machine C
export WORMHOLE_REMOTEFORWARDADDRESS=localhost:8080 # interface and port to open on machine C

./wormhole
```

### run on machine A
```bash
ssh testuser@machineB.com -p 2022 -R localhost:1234:localhost:80
```

Now you will be able to access port 80 on machineA connecting to port
8080 on machine C.
