
# Sphere 1.5.0.0 (MANDATORY UPDATE)  

### Sphere is a PoS-based cryptocurrency.

SPHR is dependent upon libsecp256k1 by sipa, the sources for which can be found here:
https://github.com/bitcoin/secp256k1

### PoW Rewards (PoW is now over)  

* 1 - 90 = 180 coins (reward "early adopters")  
* 91 - 180 = 360 coins (reward "early adopters")  
* 181 - 360 = 180 coins  
* 361 - 1080 = 90 coins  
* 1081 - 3600 = (smooth halving from 45 SPHR until the end of PoW)  

### PoS Rewards:  

* 3600 - 4100 = 3600 coins  
* 4101 - 5000 = 360 coins  
* 5001 - 12500 = 36 coins  
* 12501 - 125000 = 3.6 coins  
* 125001 - forever = 0.36 coins  

Coins mature and are ready to be staked after 6 hours.

### Masternodes (now active)  

Collateral = 50,000 SPHR  

### Tor  

Hidden service seed node on virtual port 37544:

    gqunlgogqx7x42zy.onion  

If you have TOR you can either connect only to tor nodes:

    ./sphere-qt -onlynet=Tor -listen=0 -irc=0 -proxy=127.0.0.1:9050 -addnode=gqunlgogqx7x42zy.onion:37544

Or connect to it as well as normal nodes:

    ./sphere-qt -proxy=127.0.0.1:9050 -tor=127.0.0.1:9050 -addnode=gqunlgogqx7x42zy.onion:37544

### Address Index

SPHR includes an Address Index feature, based on the address index API (searchrawtransactions RPC command) implemented in Bitcoin Core but modified implementation to work with the SPHR codebase (PoS coins maintain a txindex by default for instance).

Initialize the Address Index By Running with -reindexaddr Command Line Argument. It may take 10-15 minutes to build the initial index.





