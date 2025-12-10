---
title: Halo博客系统审计
published: 2025-12-10
description: 先写一个Person类
tags: [Example, Video]
category: Examples
draft: false
---




# 项目搭建

轻快，简洁，功能强大，使用 Java 开发的博客系统。

| 软件名称 | **版本**                                                     |
| :------: | ------------------------------------------------------------ |
| 操作系统 | Windows10                                                    |
|   Java   | JDK1.8_261（https://www.oracle.com/co/java/technologies/javase/javase8-archive-downloads.html，往下滑） |
|  Maven   | 3.6.3                                                        |
|   IEDA   | 2025.1                                                       |

源码下载地址： https://github.com/halo-dev/halo/releases/tag/v0.4.3

下载完成后解压项目文件，使用 IDEA 以 Maven 方式打开该项目即可，会自动加载相关依赖。

该系统使用了 H2 Database 作为数据库，则不需要像 Mysql 那般操作。

进入 ``src/main/java/cc/ryanc/halo/Application.java ``代码中启动项目，如下图所示

![4d6faf6f772a3914f85d8321557c7f7b](D:/0AGitHub/origin618.github.io/src/assets/images/4d6faf6f772a3914f85d8321557c7f7b.png)

访问上述提供的地址 http://localhost:8090 ，进入安装向导，内容自行填写即可



![image-20251210131414824](C:/Users/11033/AppData/Roaming/Typora/typora-user-images/image-20251210131414824.png)

备注：

- 如若遇到报错，可能是依赖未正确下载或加载所致。请尝试重启 IDEA；若问题仍未解决，请整理详细报错信息在群内咨询。

- 如若系统中安装了多个 JDK 版本，请务必前往``文件 - 项目结``（英文版请参考截图位置），将 JDK 版本设置为 **JDK1.8_291**，如下图所示：

![3b8f2082-3c09-4fa8-a80e-ada732e72b96](D:/0AGitHub/origin618.github.io/src/assets/images/3b8f2082-3c09-4fa8-a80e-ada732e72b96.png)

# 代码审计漏洞挖掘

在 Halo 0.4.3 版本中多个依赖存在 CVE 漏洞，可使用较为新版本的 IDEA 在 pom.xml 处查看

![d75d270e-6090-49c7-a6e2-50563965d9f7](D:/0AGitHub/origin618.github.io/src/assets/images/d75d270e-6090-49c7-a6e2-50563965d9f7.png)

# 任意文件删除漏洞代码审计

梳理文章功能时，发现后台设置下博客备份功能存在一个删除功能，通过抓包发现是根据文件名进行的

删除操作，可能存在任意文件删除漏洞，如下图所示：

![d6080d25-fecf-44fd-852b-266c68c5a3b8](D:/0AGitHub/origin618.github.io/src/assets/images/d6080d25-fecf-44fd-852b-266c68c5a3b8.png)

通过抓包获取到接口名为 /admin/backup/delBackup ，通过关键字逐一尝试，最终使用关键字

delBackup 定位到该接口的 Controller 层代码为 BackupController，如下图所示：

