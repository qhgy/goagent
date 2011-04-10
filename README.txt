GoAgent FAQ https://github.com/phus/goagent

Q: GoAgent是什么？
A: GoAgent是一个使用Python和Google Appengine SDK编写的代理软件。

Q: 如何部署和使用GoAgent?
A: 1.申请Google Appengine并创建appid
   2.下载GoAgent https://github.com/phus/goagent/archives/master 
   3.双击server\upload.bat,输入你的appid和你的用户名密码，上传服务端
   4.把local\proxy.ini中的your_appid改成你申请到的appid
   好了，现在你可以运行taskbar.exe来翻墙了。

Q: 既然已有WallProxy/GappProxy，为什么需要有GoAgent?
A: WallProxy项目关闭了，GappProxy半年没更新。为了应对GFW，需要一个更新快的GoAgent。

Q: 比WallProxy/GappProxy强在哪里？
A: 更新快，速度快，翻墙能力强。

Q: 需要装Python或者Google Appenginge SDK后才能用GoAgent吗？
A: 完全不用，GoAgent是绿色软件哦。

Q: GoAgent有哪些弱点？
A: 为了简单快速，GoAgent的数据基本是明文的(head+gzip)

Q: 为什么要叫GoAgent，而不叫GoProxy？
A: 一开始叫GoProxy的，后来Hewig说软件名字带有proxy字样不吉利，于是就改成了GoAgent。
   
Q: 为什么有时候GoAgent运行得好好的，突然出来一个502错误？
A: 有两种原因，1.配置错误，具体请看 http://65px.com/1993 ，2.撞墙了，GoAgent此时会尝试重连,试试刷新一下浏览器就好了。

Q: Firefox怎么不能登陆一些https网站?
A: 打开FireFox->选项->高级->加密->查看证书->导入证书, 选择local\ssl\ca.crt, 勾选所有项，导入。

Q: 为什么一运行GoAgent后，py25.exe占用了40M内存？
A: GoAgent使用psyco1.6提速，所以内存占用有点多。如果你不希望使用这个机制的话，请下载这个py25.exe然后替换 https://github.com/phus/python-tools/blob/master/py25.exe?raw=true

Q: 如何得到GoAgent的源代码？
A: GoAgent的代码和程序是一起的，源代码就是运行程序。

Q: 如何对GoAgent进行修改？
A: 客户端代码直接改local/proxy.py,改完重启taskbar.exe即可；服务端改server/fetch.py,改完用upload.bat上传即可。

Q: 已做的工作和将要做的工作？
A:  DONE:
    1. 随机获取proxy.ini中配置的可用fetch ip,提高翻墙能力
    2. 对于google的某些https域名，直接启用转发。
    3. 移植了wallproxy的_RangeFetch，支持youtube
    TODO:
    1. 支持多个fetch server 
    2. 实现xmpp fetch

Q: 有问题怎么办？
A: 请发信给我，我会把问题加到本页面的。
 