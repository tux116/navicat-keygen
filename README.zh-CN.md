# Navicat Keygen

这份repo将会告诉你Navicat是怎么完成离线激活的。

[注册机是怎么工作的?](HOW_DOES_IT_WORK.zh-CN.md)

__注意：仅支持Navicat Premium。__

## 1. 如何编译

* 在编译之前，你应该确保你有如下几个库：

  ```
  openssl
  capstone
  keystone
  rapidjson
  libplist
  ```
  
  如果你有`brew`的话，你可以通过
  
  ```
  $ brew install openssl
  $ brew install capstone
  $ brew install keystone
  $ brew install rapidjson
  $ brew install libplist
  ```
  
  来完成它们的安装。

* Clone `mac` 分支，并编译keygen和patcher

  ```bash
  $ git clone -b mac --single-branch https://github.com/DoubleLabyrinth/navicat-keygen.git
  $ cd navicat-keygen
  $ make all
  ```

  编译完成后你会在 `bin/` 文件夹下看到两个可执行文件： 

  ```bash
  $ ls bin/
  navicat-keygen    navicat-patcher
  ```

## 2. 如何使用这个Keygen

1. 编译好keygen和patcher。__并且打开Navicat Premium至少一次。

2. 备份好Navicat中所有已保存的数据库连接（包括密码）。

3. 移除所有Navicat在 `Keychain Access.app` （即钥匙链）中保存的连接，如果有的话。

   你可以通过在 `Keychain Access.app` 中搜索关键词 `navicat` 来找到它们。

4. 使用`navicat-patcher`替换掉公钥：

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

   __例如：__

   ```console
   $ ./navicat-patcher /Applications/Navicat\ Premium.app/
   ```

   __Navicat Premium For Mac 15.0.4 英文版__ 已通过测试。样例输出见[这里](example/navicat-patcher.txt)。

   * __仅对 Navicat Premium 版本 < 12.0.24 的说明：__

     如果你的Navicat版本小于12.0.24，那么`navicat-patcher`将会终止并且不会修改目标文件。
   
     你必须使用openssl生成`RegPrivateKey.pem`和`rpk`文件：

     ```console
     $ openssl genrsa -out RegPrivateKey.pem 2048
     $ openssl rsa -in RegPrivateKey.pem -pubout -out rpk
     ``` 

     接着用刚生成的`rpk`文件替换

     ```
     /Applications/Navicat Premium.app/Contents/Resources/rpk
     ```

5. __生成一份自签名的代码证书，并总是信任该证书。这一步非常重要。__

   __然后用 `codesign` 对 `libcc-premium.dylib` （如果有的话） 和 `Navicat Premium.app` 重签名。__

   * __如果你的Navicat Premium版本号高于15.0.0，__

     __你必须先签名 `libcc-premium.dylib`，再签名 `Navicat Premium.app`。__

     ```console
     $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>/Contents/Frameworks/libcc-premium.dylib
     ```

   ```console
   $ codesign -f -s "Your self-signed code-sign certificate name" <path to Navicat Premium.app>
   ```

   __注意：__ 
   
   "Your self-signed code-sign certificate name"是你证书的名字，不是路径。

   __例如：__

   ```console
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/Contents/Frameworks/libcc-premium.dylib
   $ codesign -f -s "foobar" /Applications/Navicat\ Premium.app/
   ```

6. 接下来使用`navicat-keygen`来生成 __序列号__ 和 __激活码__。

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

   __例如：__ 

   ```console
   $ ./navicat-keygen ./RegPrivateKey.pem
   ```

   你会被要求选择Navicat的语言以及输入主版本号。之后会随机生成一个 __序列号__。

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

   你可以使用这个 __序列号__ 暂时激活Navicat。

   接下来你会被要求输入`用户名`和`组织名`；请随便填写，但不要太长。

   ```console
   [*] Your name: DoubleLabyrinth
   [*] Your organization: DoubleLabyrinth

   [*] Input request code in Base64: (Double press ENTER to end)
   ```
 
   之后你会被要求填入请求码。注意 __不要关闭注册机__。

7. __断开网络__ 并打开Navicat。

   找到`注册`窗口，填入注册机给你的序列号。然后点击`激活`按钮。

8. 一般来说在线激活肯定会失败，这时候Navicat会询问你是否`手动激活`，直接选吧。

9. 在`手动激活`窗口你会得到一个请求码，复制它并把它粘贴到keygen里。最后别忘了连按至少两下回车结束输入。

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

10. 如果不出意外，你会得到一个看似用Base64编码的激活码。

    直接复制它，并把它粘贴到Navicat的`手动激活`窗口，最后点`激活`按钮。
    
    如果没什么意外的话应该能成功激活。
