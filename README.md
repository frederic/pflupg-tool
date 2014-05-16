# pflupg-tool

## Introduction
pflupg-tool is an unpacking tool for Philips SmartTV firmware (Fusion platform). If your firmware is encrypted, you have to provide the corresponding public key (public exponent + modulus).

## Code
https://github.com/frederic/pflupg-tool

## Customize
You can add public keys in pflupg.h file:
> #define PUBLIC_KEYS_CNT 2
> // { name, public exponent e (hex string), modulus n (hex string)}
> static const char *public_keys[PUBLIC_KEYS_CNT][3] = {
>  {"my_key_1", "010001", "AABBCCDD"},
>  {"my_key_2", "010001", "010E020F"}
> };

## Build
You'll need Libgcrypt library to compile it. Then:

> $ make

## Usage
> Usage: ./pflupg <upg_filename> [key_name]
> 2 keys available :
> * my_key_1
> * my_key_2

## License
GPL v2
