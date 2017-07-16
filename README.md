# fwknop - Software Defined Perimeter Client and Gateway Components

## Description
This project is an open source implementation of the client and gateway 
components for a Software Defined Perimeter (SDP). This code has been tested 
on *nix type systems only.

For more information on SDP, see the following sites:

http://www.waverleylabs.com/services/software-defined-perimeter/

https://cloudsecurityalliance.org/group/software-defined-perimeter/

## Introduction
This project is a fork of the fwknop project. fwknop originally implemented 
an authorization scheme known as Single Packet Authorization (SPA) for strong 
service concealment. Because SPA later became the basis for SDP, fwknop was 
forked and built upon to implement the additional features required to create 
an SDP system. The only component of SDP not included in this repo is the 
controller, which is also freely available at:

https://github.com/WaverleyLabs/SDPcontroller

## Tutorial
A manual for installation and configuration of SDP can be found here:

[Waverley Labs OpenSDP Installation and Configuration.pdf (in the root folder of this project)](https://github.com/WaverleyLabs/fwknop/blob/master/Waverley%20Labs%20OpenSDP%20Installation%20and%20Configuration.pdf)

A comprehensive tutorial on SPA (and how fwknop used to work) can be found here:

[http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html)



## License
The fwknop project is released as open source software under the terms of
the **GNU General Public License (GPL v2)**. 


## Building fwknop
This distribution uses GNU autoconf for setting up the build. Please see
the `INSTALL` file for the general basics on using autoconf.

There are some "configure" options that are specific to fwknop. They are
(extracted from *./configure --help*):

      --disable-client        Do not build the fwknop client component. The
                              default is to build the client.
      --disable-server        Do not build the fwknop server component. The
                              default is to build the server.
      --with-gpgme            support for gpg encryption using libgpgme
                              [default=check]
      --with-gpgme-prefix=PFX prefix where GPGME is installed (optional)
      --with-gpg=/path/to/gpg Specify path to the gpg executable that gpgme will
                              use [default=check path]
      --with-firewalld=/path/to/firewalld
                              Specify path to the firewalld executable
                              [default=check path]
      --with-iptables=/path/to/iptables
                              Specify path to the iptables executable
                              [default=check path]
      --with-ipfw=/path/to/ipfw
                              Specify path to the ipfw executable [default=check
                              path]
      --with-pf=/path/to/pfctl
                              Specify path to the pf executable [default=check
                              path]
      --with-ipf=/path/to/ipf Specify path to the ipf executable [default=check
                              path]

    Examples:

    ./configure --disable-client --with-firewalld=/bin/firewall-cmd
    ./configure --disable-client --with-iptables=/sbin/iptables --with-firewalld=no

