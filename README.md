# 简介

这个仓库是一群对技术还尚有激情的人，对Linux内核的一些理解，我们欢迎大家批评指正，以真正理解Linux内核。

## 目录组织形式

每一个章节用一个文件夹，比如下面的示例：

+ 第一章：Linux内核之进程
  + 1.1 ...
  + 1.2 ...
+ 第二章：Linux内核之内存
  + 2.1 ...
  + 2.2 ...
  
## 提交规范

我们会设置一个master主分支，作为我们的基准分支，采用分支法进行文档的提交，每个人可以创建自己的临时分支，完成文档编写后提交到自己的分支，发起一个合并请求，指定审核人，在审核通过之后可以merge到master分支，展示下如何完成一次文档提交：

```bash
git clone https://github.com/RTFScode/kernel-wiki.git
cd kernel-wiki


# 切换到自己的临时分支
git checkout -b t/ali-process

# 完成文档编写

# 提交
git add youfile

# 补充完整的说明信息
git commit 

# 提交自己的临时分支
git push origin t/ali-process

# 在界面发起自己的合并请求，并制定审核人
``` 