# autoli

### 项目描述
面向汽车研发测试领域，包括但不限于Linux系统、web页面、http接口、DoIP、PCAN等车云E2E的系统测试框架

### 环境依赖
Python 3.11.7 (tags/v3.11.7:fa7a6f2, Dec  4 2023, 19:24:49) [MSC v.1937 64 bit (AMD64)] on win32

### 环境配置
- 电检诊断CAN/LIN相关测试需要安装 PcanView相关驱动
  * 安装教程见官网：https://www.peak-system.com/PCAN-View.242.0.html?&L=1
  * 安装完成后，配置 PcanView.exe的环境变量
  * 打开windows环境变量
  * 新建变量 PCAN_PATH，添加 PcanView.exe 的绝对路径
  
### 目录结构描述
```
├── action                                  // 测试行动包, 提供各种测试操作步骤  
│    └── establish                          // 执行类
│    └── state                              // 查询类
├── aplications                             // 平台内置的应用
│    └── lpai                               // 操作lpai进行数据分析
│    └── stars                              // 星辰监控系统
│    └── vv_bot                             // 飞书机器人服务端，告警任务等
├── common                                  // 公共接口包, 提供各业务功能与服务模块  
│    └── api_xxx.py                         // 各平台http接口 
│    └── decorators.py                      // 装饰器模块，提供各种类，函数等装饰器  
│    └── exception.py                       // 自定义异常处理模块，输出各异常信息  
│    └── log.py                             // 日志模块，提供项目运行的日志输出和日志文件保存功能  
│    └── protocol.py                        // 协议模块，自定义协议  
├── config                                  // 配置目录，存放各种配置文件   
│    └──config.ini                          // 项目配置文件，存放项目全局配置信息  
│    └──set_env.py                          // 环境配置模块，用于配置项目的环境，设置全局参数等  
│    └──mapping.py                          // 诊断CAN矩阵路由关系与PCAN配置等  
│    └──tcf.ini                             // test config file，全局配置文件选择  
├── src                                     // 存放各用例数据与测试结果文件  
├── logs                                    // 测试日志目录，存放历史日志文件，不纳入VC管理  
├── reports                                 // 测试报告目录，存放历史报告文件，不纳入VC管理  
├── scripts                                 // 脚本库，一般用于写测试工具和调试使用  
├── testcases                               // 测试用例存放目录，以.py为单位的测试用例集，unittest框架编写测试用例  
├── tests                                   // 平台的代码测试目录，存放平台各单元测试和功能测试模块  
├── utilities                               // 功能包集合  
│    └── jira                               // 操作jira接口  
│    └── os                                 // 提供当前系统操作方法  
│    └── time                               // 提供时间操作方法  
│    └── browser                            // 提供selenium浏览器操作方法  
│    └── db                                 // 提供各种数据库操作方法  
│    └── dds                                // 提供rti-dds协议交互组件，需要安装connextdds-py包  
│    └── feishu                             // 操作飞书接口，飞书webhook机器人等  
│    └── files                              // 操作各种类型的文件，如json、excel、xml、yaml等  
│    └── linux                              // linux系统交互集成方法  
│    └── lua                                // lua脚本操作方法  
│    └── ota                                // ota测试引擎，ota文件服务器等  
│    └── parser                             // 提供各种数据类型，常用协议的解析方法，如解析字符串，列表，http协议等  
│    └── pcan                               // 用于pcan设备交互，CAN报文的发送与接收  
│    └── performance                        // 性能监控模块，提供CPU与内存监控功能  
│    └── plin                               // 用于pcan设备交互，LIN报文的主从收发功能  
│    └── runner                             // unittest测试渲染器如 XML,HTML等   
│    └── simulation                         // 各仿真测试相关主程序，当前有诊断，电检，OTA等   
├── README.md                               // 项目描述文档  
├── .gitignore                              // 版本控制规则文件  
├── requirements.txt                        // 第三方依赖包与版本信息, pip install -r requirements.txt  
├── run.py                                  // 测试运行模块，车云自动化测试运行入口，调用 python run.py [options] [args] 运行 
```