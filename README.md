基于C/CPP的调试器



### 示例

1. 显示修改反汇编:

    mfas 7786e9e6 mov ecx,1;

    shas 7786e9e6 10

2. 查看修改寄存器

    shrg

    mfrg ecx 1

3. 查看内存，修改内存，查看堆栈

    shmm 7786e9e6 10

    mfmm 7786e9e6 abcd

4. 查看模块信息

    shmd

5. 单步

    sfbp 411a40

    stin

6. 步过

    sfbp 411a6e

    ston

7. 软件断点 （永久断点）

    sfbp 411a40	(main) 

    sfbp 411a95(永久)

8. 硬件执行断点 ， 硬件访问断点，硬件写入断点

    ston（系统断点后

    hdex 7786e9ed

    hdrw 19fa3c 3（ebp-10，7786e9e3

9. 内存访问断点, 内存执行断点，内存写入断点

    mmbp 7786e9ed

    mmbp 19fa3c （ebp-10，7786e9e3

10. 条件断点

    cdbp 411a95 3



### 功能截图

1-显示修改反汇编
![](http://img2.21guns.top/2020-02-15-080951.jpg)

2-显示修改寄存器
![](http://img2.21guns.top/2020-02-15-080944.jpg)

3-显示修改内存:栈
![](http://img2.21guns.top/2020-02-15-080856.jpg)

4-显示模块信息
![](http://img2.21guns.top/2020-02-15-080949.jpg)

5-单步断点
![](http://img2.21guns.top/2020-02-15-080943.jpg)

6-单步步过
![](http://img2.21guns.top/2020-02-15-080946.jpg)

7-软件断点-永久断点
![](http://img2.21guns.top/2020-02-15-080855.jpg)

8-硬件执行断点
![](http://img2.21guns.top/2020-02-15-080952.jpg)

8-硬件读写断点
![](http://img2.21guns.top/2020-02-15-080937.jpg)

9-内存执行断点
![](http://img2.21guns.top/2020-02-15-080942.jpg)

9-内存访问断点
![](http://img2.21guns.top/2020-02-15-080853.jpg)

10-条件断点
![](http://img2.21guns.top/2020-02-15-080938.jpg)

11-反调试
![](http://img2.21guns.top/2020-02-15-080948.jpg)

12-支持插件
![](http://img2.21guns.top/2020-02-15-080940.jpg)