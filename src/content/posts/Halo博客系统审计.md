---
title: Halo博客系统审计
published: 2025-11-05
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
|   IEDA   | 2022.3                                                       |

源码下载地址： https://github.com/halo-dev/halo/releases/tag/v0.4.3

下载完成后解压项目文件，使用 IDEA 以 Maven 方式打开该项目即可，会自动加载相关依赖。

该系统使用了 H2 Database 作为数据库，则不需要像 Mysql 那般操作。

进入 src/main/java/cc/ryanc/halo/Application.java 代码中启动项目，如下图所示

![4d6faf6f772a3914f85d8321557c7f7b](src\assets\images\4d6faf6f772a3914f85d8321557c7f7b.png)
