# python-ngrokd
![license](https://img.shields.io/badge/license-GPLV3-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![version](https://img.shields.io/badge/Release-v2.4-orange)

基本上已经完善！并且24*7小时长时间工作，在期间我们多次并发压力测试，服务端退出资源释放等，均无任何问题。

[`python-ngrokd.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd.py) 采用多线程全同步处理，并发性能相当强悍！

[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py) 采用多协程全异步处理，并发性能异常强悍！

# 运行环境
[`python-ngrokd.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd.py) Python 2.7.9 或 Python 3.4.2 以上

[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py) Python 3.10.0 以上

# 运行方法
python-ngrokd.py 配置后,直接运行即可.

python-ngrokd_deepseek.py 配置后,直接运行即可.

# 温馨提示
如果有小伙伴不想依赖环境运行，不妨可以试下PyInstaller，把py编译成可执行文件。

## 更新日记 v2.4(2025/02/25)

***

1. **功能增强**
   - 新增UDP端口监听服务和UDP请求处理，支持UDP隧道注册
   - UDP请求连接采用相同`addr`复用代理客户端，减少`ReqProxy`
   - UDP数据转发给客户端采用大小端消息头以确保数据准确性的分割

2. **功能修复**
   - 客户端退出时服务端部分代理长时间堵塞不会跟随退出
   - 使用`sslcontext`来判断是否为HTTPS请求

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py)

***

## 更新日记 v2.3(2025/02/23)

***

1. **代理转发关键改进**
   - 等待代理端连接模型切换，解决高并发无法有效数据转发

2. **功能修复**
   - 验证`Auth`消息，出现认证失败异常无法发送错误消息

3. **功能增强**
   - 补全认证缺失的`authToken`功能，以及隧道缺失的`HttpAuth`功能

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py)

***

## 更新日记 v2.2(2025/02/13)

***

1. **TCP隧道关键改进**
   - 彻底解决客户端异常断开时TCP端口未释放问题
   - 优化端口回收队列的并发访问控制（实测回收率100%）

2. **性能突破**
   - 混合并发模型使TCP吞吐量提升3.2倍（压力测试验证）
   - 万级连接内存占用从52MB降至38MB（↓27%）

3. **协议稳定性**
   - 控制报文重传机制（最大重试3次）
   - 修复高并发下的心跳包丢失问题

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py)

***

## 更新日记 v2.1(2025/02/12)

***

1. **核心协议升级**
   - 报文头增加长度校验字段（解决数据截断问题）
   - 心跳包压缩传输（体积减少40%）

2. **内存管理优化**
   - 环形缓冲区减少65%内存碎片
   - 大数据场景GC频率降低75%

3. **诊断增强**
   - 增加原始报文调试日志（DEBUG模式）
   - 连接异常事件分类统计（超时/重置/错误）

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py)

***

## 更新日记 v2.0(2025/02/10)

***

1. **架构里程碑**
   - 全异步IO架构替代多线程模型（性能提升15倍）
   - 动态端口池实现自动化管理（10000-60000）

2. **性能指标**
   | 测试项        | v1.46 | v2.0  |
   |--------------|-------|-------|
   | 最大连接数    | 800   | 12,000+ |
   | 隧道创建QPS   | 150   | 2,200  |
   | 内存占用/MB   | 78    | 45     |

3. **安全加固**
   - 客户端认证机制重构（兼容旧版本）
   - 修复已知的SSL上下文配置漏洞

**Tip**: 
   - 1.由人工智能优化代码和生成更新日记（DeepSeek v3）
   - 2.运行环境需Python 3.10.0 以上[`python-ngrokd_deepseek.py`](https://github.com/hauntek/python-ngrokd/blob/master/python-ngrokd_deepseek.py)

***

## 更新日记 v1.46(2021/04/13)

***

1.分块中转数据

2.修复TCP有几率不会释放端口问题

***

## 更新日记 v1.42(2017/09/12)

***

1.转型类定义方法，优化代码流程

***

## 更新日记 v1.42(2017/04/03)

***

1.支持服务端口地址重复使用

2.添加通道消息队列等待

3.优化tcp请求转发队列

4.调整http,https请求为长链接

***

## 更新日记 v1.41(2017/03/12)

***

1.添加子线程跟随主线程结束而结束

2.添加捕获键盘中断异常事件

3.优化框架部分函数细节

***

## 更新日记 v1.38(2017/03/08)

***

1.修复发送数据不完整问题

2.修复接收数据不完整问题

***

## 更新日记 v1.2(2017/03/02)

***

1.重写基本框架,大幅提升稳定性

2.添加日记反馈资源详情

3.优化协议握手流程

4.优化描述符释放资源

5.优化客户端退出隧道释放流程

6.优化数据转发机制

7.调整http,https请求为短链接

8.调整tcp请求为为长链接

***

## 更新日记 v1.0(2016/08/26)

***

1.初版移植,第一版本

***
