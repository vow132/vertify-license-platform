"""
实验性 Python 协议示例。
注意：当前服务端要求设备 PoP 签名和 /v1/heartbeat，Python 示例尚未实现完整协议，不能用于生产激活。
请使用 sdk/windows-cpp；本文件仅供协议结构参考。
"""
from lumistar_client import LumistarClient

# ===== 你的脚本入口 =====
def main():
    # ---- 第 1 步：激活 ----
    v = LumistarClient(
        server="https://127.0.0.1:8443",     # 你的验证服务器
        card="",                              # 用户输入的卡密，首次激活后可留空
        product="AUXPRO",                     # 产品代码
        client_version="1.0.0",
    )
    # 如果没有已激活的卡密，提示用户输入
    if not v.card:
        v.card = input("请输入卡密：").strip()
        if not v.card:
            print("未输入卡密，退出")
            return

    print("正在激活…")
    if not v.activate():
        print(f"激活失败: {v.error}")
        print("可能原因：卡密无效/已过期/已冻结/设备已达上限")
        input("按回车退出")
        return

    print(f"✓ 激活成功！功能: {v.features}")

    # ---- 第 2 步：启动心跳（后台自动续租，不用管） ----
    v.start_heartbeat()

    # ---- 第 3 步：你的脚本主循环 ----
    # 每次执行功能前检查 v.authorized / v.has_feature("xxx")
    import time
    while True:
        if not v.authorized:
            print("授权已失效，请重新激活或续费")
            break

        # ===== 这里放你脚本的实际逻辑 =====
        print(f"[授权有效] 剩余功能: {v.features}")

        # 示例：按功能权限执行
        if v.has_feature("aimbot"):
            pass  # do_aimbot()
        if v.has_feature("esp"):
            pass  # do_esp()

        time.sleep(5)


if __name__ == "__main__":
    main()
