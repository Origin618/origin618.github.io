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

下载完成后解压项目文件，使用 IDEA 以 Maven 方式打开该项目即可

该系统使用了 H2 Database 作为数据库，不需要像 Mysql 那般操作。

进入 ``src/main/java/cc/ryanc/halo/Application.java ``代码中启动项目，如下图所示

![6aac20cb-8c9b-42a9-817f-0489f0918f9f](/public/6aac20cb-8c9b-42a9-817f-0489f0918f9f.png)

访问上述提供的地址 http://localhost:8090 ，进入安装向导



![image-20251210131414824](C:/Users/11033/AppData/Roaming/Typora/typora-user-images/image-20251210131414824.png)

备注：

- 如若遇到报错，可能是依赖未正确下载或加载所致。请尝试重启 IDEA

- 如若系统中安装了多个 JDK 版本，请务必前往``文件 - 项目结``（英文版请参考截图位置），将 JDK 版本设置为 **JDK1.8_291**，如下图所示：

![0249ff1d-8a95-48b1-897d-3ea81c1b2350](/public/0249ff1d-8a95-48b1-897d-3ea81c1b2350.png)

# 代码审计漏洞挖掘

在 Halo 0.4.3 版本中多个依赖存在 CVE 漏洞，可使用较为新版本的 IDEA 在 pom.xml 处查看

![d75d270e-6090-49c7-a6e2-50563965d9f7](D:/0AGitHub/origin618.github.io/src/assets/images/d75d270e-6090-49c7-a6e2-50563965d9f7.png)

# 任意文件删除漏洞代码审计

梳理文章功能时，发现后台设置下博客备份功能存在一个删除功能，通过抓包发现是根据文件名进行的

删除操作，可能存在任意文件删除漏洞：

![d6080d25-fecf-44fd-852b-266c68c5a3b8](D:/0AGitHub/origin618.github.io/src/assets/images/d6080d25-fecf-44fd-852b-266c68c5a3b8.png)

通过抓包获取到接口名为 ``/admin/backup/delBackup`` ，通过关键字一一尝试，最终使用

``delBackup`` 定位到该接口的 Controller 层代码为 BackupController：

![image-20251210145055635](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210145055635.png)

我们进入 BackupController 层，具体代码位于第 211 行至第 220 行

![image-20251210145438312](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210145438312.png)

第一步，双击213行的filename参数，通过高亮 ``fileName ``以及 ``type ``参数，在第 215 行处被

使用

![image-20251210145848758](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210145848758.png)

第二步，分析第 215 行，代码拼接了用户的主目录路径加上 ``/halo/backup/ ``加上传递来的

type 参数加上传递来的 ``fileName`` 参数，最终拼接成一个完整的路径，赋值给 srcPath 参数。其中 type参

数是其中一个路径

![image-20251210145825487](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210145825487.png)

第三步，通过上图单击 ``srcPath ``的高亮显示，可以看到在第 217 行使用了 FileUtil.del 方法对

``srcPath ``进行了操作。将鼠标悬停在该方法处，可以看到是 hutool 组件下的方法。

![image-20251210150154834](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210150154834.png)

上述两步操作中可以看到，该接口并没有任何防止跨目录的操作，从功能点思考可能会造成任意文件删除漏洞。

最后，在第 217 行处打个断点进行测试

![image-20251210150428492](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210150428492.png)

## 漏洞验证

在任意文件删除单点漏洞代码审计的最后断点处，我们知道了备份文件的存储路径是C:\Users\powerful\halo\backup\posts

我们在I盘下新建一个名为`1.txt`的文件。点击删除功能点捉包

![image-20251210150852254](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210150852254.png)

在代码审计部分，我们知道 type 和 fileName 参数都拼接到了路径中

所以这两个参数都可以跨目录实现任意文件删除操作

![image-20251210152329600](C:\Users\11033\AppData\Roaming\Typora\typora-user-images\image-20251210152329600.png)

删除成功
