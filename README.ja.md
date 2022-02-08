# netenum.py

コンソールからネットワークをスキャンします。

テーブル表示のほか、JSON形式でも出力できます。

[English](README.md)


## 使い方

```bash
> python netenum.py --help
usage: netenum.py [-h] [-i [INTERFACE]] [-t [TARGET]] [-p] [-a] [-r] [-w [TIMEOUT]] [-o {table,json}] [-v]

Scan your network with ARP and Ping

optional arguments:
  -h, --help            show this help message and exit
  -i [INTERFACE], --interface [INTERFACE]
                        Interface to use
  -t [TARGET], --target [TARGET]
                        Target IPv4 address or IPv4 network
  -p, --ping            Perform Ping sweep
  -a, --arp             Perform ARP scan
  -r, --resolve         Resolve Hostname from IP
  -w [TIMEOUT], --timeout [TIMEOUT]
                        Timeout for ping/arp scan (default: 1)
  -o {table,json}, --output {table,json}
                        Output Style (default: table)
  -v, --verbose         Verbose output

!!! Please use for your own risk !!!

Created by: Neustrashimy
Report bug to: https://github.com/Neustrashimy/netenum.py/issues
```

## 例

### シンプルなPingスイープ

```bash
> python netenum.py --interface 'Ethernet 1' --target 192.168.1.0/24 --ping
+---------------+----------+----------+---------------------+
| IP            | HostName | RTT      | Time                |
+---------------+----------+----------+---------------------+
| 192.168.1.47  |          | 15.59ms  | 2022-02-08 10:19:08 |
| 192.168.1.101 |          | 15.58ms  | 2022-02-08 10:20:01 |
| 192.168.1.102 |          | 15.45ms  | 2022-02-08 10:20:01 |
| 192.168.1.254 |          | 15.79ms  | 2022-02-08 10:22:18 |
+---------------+----------+----------+---------------------+

```

### シンプルなARPスキャン

```bash
> python netenum.py --interface 'Ethernet 1' --target 192.168.1.0/24 --arp
+---------------+----------+-------------------+-------------------------------------+---------------------+
| IP            | HostName | MAC               | Vendor                              | Time                |
+---------------+----------+-------------------+-------------------------------------+---------------------+
| 192.168.1.47  |          | 48:3f:da:xx:xx:xx | Espressif Inc.                      | 2022-02-08 10:42:47 |
| 192.168.1.101 |          | e0:46:9a:xx:xx:xx | NETGEAR                             | 2022-02-08 10:43:43 |
| 192.168.1.240 |          | 84:4b:f5:xx:xx:xx | Hon Hai Precision Ind. Co.,Ltd.     | 2022-02-08 10:46:16 |
| 192.168.1.254 |          | 98:f1:99:xx:xx:xx | NEC Platforms, Ltd.                 | 2022-02-08 10:46:31 |
+---------------+----------+-------------------+-------------------------------------+---------------------+
```

## 免責事項

* 本ソフトウエアを使用した事によるいかなる損害も補償いたしません。使用者の責任においてご使用ください。
* バグ報告や提案、その他ご要望などは[Github](https://github.com/Neustrashimy/netenum.py) issue までお願いいたします。


## 謝辞

* オリジナルのNetEnumを作成・公開されている、[株式会社リアライズ](https://www.e-realize.com/)様に感謝申し上げます。 