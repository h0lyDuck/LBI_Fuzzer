# LBI_Fuzzer

## parameter_analyer

基于langchain框架实现rag分析，需要的python库在文件夹中的requirements.txt中。

## patcher

基于idapython实现桩点插入，因此需要ida支持，其余需要的python库在文件夹中的requirements.txt中。

## signal_monitor

signal_monitor需要arm的交叉编译工具链来进行编译，请修改makefile中的路径指向本地的交叉编译工具链。

1. 对于使用glibc的设备，直接安装源中的`gcc-arm-linux-gnueabi`的工具进行编译。

2. 对于使用uclibc或musl的设备，通过buildroot构建交叉编译工具链，进行编译。
    1. 下载并解压buildroot，工具下载地址http://buildroot.uclibc.org/downloads/snapshots/。
    2. 配置。
        1. 选择了configs文件夹中的qemu_arm_vexpress_defconfig文件，然后将该文件复制到buildroot文件夹下，并执行make qemu_arm_vexpress_defconfig命令进行初步配置。
        2. 终端输入make menuconfig命令，对Target options，Build options，Toolchain等选项进行设置。
            1. Target options：根据目标平台架构进行设置，还有大小端等。
            2. Build options：Host dir，这个可以自定义为/usr/local/xxx，其中xxx是自己创建的一个文件夹，名字随意。这个选项设置的好处就是方便后续的移植，可以很方便的在其他机器上使用这个编译工具。
            3. Toolchain：这个里边需要注意以下几点。① Toolchain type选择Buildroot toolchain内部工具链； ② custom toolchain vendor name就是自定义工具链的名字； ③ Kernel Headers，内核版本号，这个需要根据自己的Linux环境来选择，使用uname -a显示系统信息，选择一致的版本就可以，如果没选对的话之后可以根据报错再回来改； ④ C library也就是C库，选uclibc；
        3. 配置好以上信息，保存一下，退出即可。
        4. 终端中执行sudo make命令，等待执行完成。期间可能会出现很多报错，请看下一节。   

## fuzzer

fuzz控制器，需要的python库在文件夹中的requirements.txt中。

## target_binary

提供了针对tenda ac9的示意代码。
