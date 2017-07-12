# sxenc 0.1
Simple implementation of XOR encryption.

## Written by
Björn Westerberg Nauclér (mail@bnaucler.se) 2017

Compiled and tested on Arch Linux 4.11 (x86\_64)

## Installation
`sudo make all install` should do the trick.

## Usage
`sxenc -g 512` creates a 512 byte key and stores at $HOME/.sxkey  
`sxenc somefile` encrypts somefile to somefile.ap  
`sxenc -d somefile.ap` decrypts somefile.ap to stdout

## Disclaimer
This is a quick hack for experimental purposes and should not be used as an actual method to keep data safe.

## License
MIT (do whatever you want)
