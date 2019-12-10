# Navicat Keygen

[中文版README](README.zh-CN.md)

This repository will tell you how Navicat offline activation works.

[How does it work?](HOW_DOES_IT_WORK.md)

__NOTICE: This keygen only supports Navicat Premium.__

## 1. How to build

* Before you build keygen, you should make sure you have following libs:
 
  ```
  openssl
  capstone
  keystone
  rapidjson
  libplist
  ```

  You can install them by 
  
  ```shell
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
  $ brew install libplist
  ```

* Clone `mac` branch and build keygen and patcher:

  ```shell
  $ git clone -b mac --single-branch https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  You will see two executable files in `bin/` directory:

  ```shell
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. How to Use

1. Build keygen and patcher. __And open Navicat Premium AT LEAST ONCE!!!__

2. Backup all of your saved database connection configurations (with password). 

3. Remove all connections, if have, that Navicat saved in `Keychain Access.app`. 

   You can find them by search with keyword `navicat` in `Keychain Access.app`.

4. Use `navicat-patcher` to replace __Navicat Activation Public Key__.
   
   ```
   Usage:
       navicat-patcher [--dry-run] <Navicat installation path> [RSA-2048 Private Key File]

           [--dry-run]                   Run patcher without applying any patches.
                                         This parameter is optional.

           <Navicat installation path>   Path to `Navicat Premium.app`.
                                         Example:
                                             /Applications/Navicat\ Premium.app/
                                         This parameter must be specified.

           [RSA-2048 Private Key File]   Path to a PEM-format RSA-2048 private key file.
                                         This parameter is optional.
   ```

   __Example:__ 

   ```console
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/
   ```

   It has been tested on __Navicat Premium 15.0.4 English For Mac__ version. 
   
   An example of output can be found [here](example/navicat-patcher.txt)

   * __For Navicat Premium version < 12.0.24 ONLY:__

     `navicat-patcher` will abort and won't apply any patch. 
   
     You should use openssl to generate `RegPrivateKey.pem` and `rpk` file.
   
     ```console
     $ openssl genrsa -out RegPrivateKey.pem 2048
     $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
     ```
   
     Then replace 

     ```
     /Applications/Navicat Premium.app/Contents/Resources/rpk
     ```

     by `rpk` you just generated.

5. __Generate a self-signed code-sign certificate and always trust it.__

   __Then use `codesign` to re-sign `libcc-premium.dylib`, if have, and `Navicat Premium.app`.__

   * __If you Navicat Premium version >= 15.0.0,__
   
     __you must re-sign `libcc-premium.dylib` before re-sign `Navicat Premium.app`.__

     ```console
     $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>/Contents/Frameworks/libcc-premium.dylib
     ```

   ```console
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __NOTICE:__ 
   
   "Your self-signed code-sign certificate name" is the name of your certificate in `Keychain Access.app`, not path.

   __Example:__

   ```console
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/Contents/Frameworks/libcc-premium.dylib
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. Then use `navicat-keygen` to generate __snKey__ and __Activation Code__.

   ```
   Usage:
       navicat-keygen [--adv] <RSA-2048 Private Key File>

       [--adv]                       Enable advance mode.
                                     This parameter is optional.

       <RSA-2048 Private Key File>   A path to an RSA-2048 private key file.
                                     This parameter must be specified.

   Example:
       ./navicat-keygen ./RegPrivateKey.pem
   ```

   __Example:__

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   ```

   You will be asked to select Navicat language and give major version number. After that an randomly generated __snKey__ will be given.

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   **********************************************************
   *       Navicat Keygen (macOS) by @DoubleLabyrinth       *
   *                   Version: 5.0                         *
   **********************************************************

   [*] Select product language:
   0. English
   1. Simplified Chinese
   2. Traditional Chinese
   3. Japanese
   4. Polish
   5. Spanish
   6. French
   7. German
   8. Korean
   9. Russian
   10. Portuguese

   (Input index)> 0

   [*] Input major version number:
   (range: 0 ~ 15, default: 15)> 15

   [*] Serial number:
   NAVD-ZM3Z-BK6L-JUWD

   [*] Your name:
   ```

   You can use this __snKey__ to activate your Navicat preliminarily.
     
   Then you will be asked to input `Your name` and `Your organization`. Just set them whatever you want, but not too long.

   ```console
   [*] Your name: DoubleLabyrinth
   [*] Your organization: DoubleLabyrinth

   [*] Input request code in Base64: (Double press ENTER to end)
   ```
     
   After that, you will be asked to input request code. Now __DO NOT CLOSE KEYGEN__.

7. __Disconnect your network__ and open Navicat Premium. 

   Find and click `Registration`. 
   
   Fill license key by __Serial number__ that the keygen gave and click `Activate`.

8. Generally online activation will fail and Navicat will ask you do `Manual Activation`, just choose it.

9. Copy your request code and paste it in the keygen. Input empty line to tell the keygen that your input ends.

   ```console
   [*] Input request code in Base64: (Double press ENTER to end)
   IF+tuUn0WcDqJ0tthu/UwOxCZAz5/TqGrSG/9y5DcYJ0/5kfu11Tu314T/pUFK7WPzbnK2MFQ9kb9VytT4T10fXHKoHVYRBtOTYDQqCN2lwnmTty1i1SwUVO+CAqXasqqnss/r4ytbQUpsr2EmBqMQeXERhH72winnhfHkXoWgIHhYXgcvRBagKI1a48c8vJTjTB1eYHmO+DQI6orJoQ65ClqVSkdgKwyhAtSv0yMeKQX45UEX5hQCu9rrgqRN13f7mKWXhGZXkYrk4VZaHdfsr0o50zmU/ZhKLdFqRjrLzt4JY41+AIjAxtHd5g/LAUwBfUdfy9KdHjaeXCxdueXQ==

   [*] Request Info:
   {"K":"NAVDZM3ZBK6LJUWD", "DI":"78BC84E24E18EFCE1DF7", "P":"MAC"}

   [*] Response Info:
   {"K":"NAVDZM3ZBK6LJUWD","DI":"78BC84E24E18EFCE1DF7","N":"DoubleLabyrinth","O":"DoubleLabyrinth","T":1576005483}

   [*] Activation Code:
   dJldt4pru2xBtqWiYCdT8s8H0vQ8xe8wI/f3/BLzSf7m3gevql9Z9CfkdMpuCJg35YPYTDHBwYYLnU6heO0bmvnVAF1U6ZKtWXpAAi+w6tGjeV64uachGI+/xb5Q5bQzD0V44PGYmL6cYULYjNtndMAgzhWGFzgsjGtaJOSczWC2OI1R1gAGh+l+pFdx37+VMXtfUtwv7V+qypj5CrzIULsUdh9U5JHXkdVSK6y+8bEeplYLwvQR6Cnavra0WUAP0hSg7khjy+mPiCuXSMwH1EphFqXscp1WUGjkms7pSK/aPtCoxWcJeK3SrgAVberBn2+rqaI1PBBh5DTctDy2SQ==
   ```

10. Finally, you will get __Activation Code__ which looks like a Base64 string. 

    Just copy it and paste it in Navicat `Manual Activation` window, then click `Activate`. 
    
    If nothing wrong, activation should be done successfully.

