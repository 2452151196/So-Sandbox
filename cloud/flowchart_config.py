#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流程图配置模块
提供分支指令配置，支持动态修改
"""

# 所有跳转指令集合
BRANCH_INSTRUCTIONS = [
    "b", "bl", "br", "blr", "ret",
    "cbz", "cbnz", "tbz", "tbnz",
    "b.eq", "b.ne", "b.cs", "b.hs",
    "b.cc", "b.lo", "b.mi", "b.pl",
    "b.vs", "b.vc", "b.hi", "b.ls",
    "b.ge", "b.lt", "b.gt", "b.le", "b.al"
]

# 条件跳转指令集合（用于判断是否需要创建分支）
CONDITIONAL_BRANCH_INSTRUCTIONS = [
    "cbz", "cbnz", "tbz", "tbnz",
    "b.eq", "b.ne", "b.cs", "b.hs",
    "b.cc", "b.lo", "b.mi", "b.pl",
    "b.vs", "b.vc", "b.hi", "b.ls",
    "b.ge", "b.lt", "b.gt", "b.le", "b.al"
]

def get_branch_instructions():
    """获取所有跳转指令配置"""
    return {
        "branch_insns": BRANCH_INSTRUCTIONS,
        "cond_branch_insns": CONDITIONAL_BRANCH_INSTRUCTIONS,
        "version": "1.0"
    }

def update_branch_instructions(new_branch, new_cond_branch):
    """更新指令配置（用于动态修改）"""
    global BRANCH_INSTRUCTIONS, CONDITIONAL_BRANCH_INSTRUCTIONS
    BRANCH_INSTRUCTIONS = new_branch
    CONDITIONAL_BRANCH_INSTRUCTIONS = new_cond_branch
    return True
