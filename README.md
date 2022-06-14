# thesis-ma

### Abstract

In the last years, botnets present a growing threat to end-users and network administrators alike. The large networks of infected hosts are able to deliver massive DDoS attacks and allow the botmaster to exfiltrate data from the bots in nearly untraceable ways. With the evolution from centralized architectures to P2P networks botnet became more resilient to takedown attempts by law enforcement. As such monitoring is more important then ever to evaluate the threats posed by them. Because of their resilience, exploiting vulnerabilities in communication protocols is often the only way to take down a botnet.
This thesis analyzes and monitors one of the most dangerous botnets today, the Dridex financial trojan, with a focus on its P2P protocol. It provides byte-level descriptions of request and response messages to bootstrap further research. Addtitionally, details of the sophisticated module execution process as well as the bot main module’s internal architecture are presented. To verify our findings about the malware the Dridex L2 Scanner was developed, applied to large IP-address ranges from Great Britain and Europe and revealed 42 total super peers which were then monitored for a short timespan.
From a protocol standpoint no immediate vulnerabilities could be found in the analyzed messages of Dridex’s P2P communication besides a minor information leak. Future research should continue this research to support future takedown attempts.

### Building instructions

The thesis is written in LaTex so you will need a working Tex installation (usually TexLive on *nix systems) to compile it successfully. For convenience there is a `Makefile` in the text folder that will compile everything (including sources) and output a single file `thesis.pdf`.

TL;DR

    $ git clone http://github.com/1wilkens/thesis-ma.git
    $ cd thesis-ma/text
    $ make pdf
    $ <pdfviewer> thesis.pdf

### LICENSE

All code written is licensed under the MIT license unless stated otherwise.

