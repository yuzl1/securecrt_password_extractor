import os
import re
import csv
import sys

# 尝试导入加密库
try:
    from securecrt_cipher import SecureCRTCrypto, SecureCRTCryptoV2
except ImportError:
    print("错误: 找不到 securecrt_cipher.py 文件，请确保它在当前目录下。")
    sys.exit(1)

# ======================== 配置常量 ========================
CSV_HEADERS = ["目录层级", "文件名", "用户名", "明文密码", "密码版本"]
OUTPUT_CSV = 'securecrt_passwords.csv'

# ======================== 辅助函数 ========================
def extract_password_info(file_path):
    """
    智能检测编码并从INI文件中提取密码信息和用户名
    """
    # 正则表达式定义
    password_v2_pattern = re.compile(r'S:"Password V2"\s*=\s*(\w+):([0-9a-fA-F]+)')
    password_v1_pattern = re.compile(r'S:"Password"\s*=\s*u([0-9a-fA-F]+)')
    # 更加通用的用户名匹配
    username_pattern = re.compile(r'S:"Username"\s*=\s*(.*?)(?:\r?\n|$)')

    content = None
    # 智能尝试多种可能的编码格式
    # utf-8-sig 处理带BOM的UTF-8
    # utf-16-le 处理不带BOM的UTF-16 (SecureCRT 常用)
    encodings = ['utf-8-sig', 'utf-16', 'utf-16-le', 'utf-8', 'gbk']
    
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                content = f.read()
                # 校验：内容中应该包含 S:"，否则说明读出来是乱码
                if 'S:"' in content:
                    break
        except Exception:
            continue

    if content is None:
        print(f"读取文件失败 (尝试了所有已知编码): {file_path}")
        return None

    # 提取用户名
    username_match = username_pattern.search(content)
    username = username_match.group(1).strip() if username_match else ""

    # 优先查找V2版本密码
    v2_match = password_v2_pattern.search(content)
    if v2_match:
        return {
            'version': 'V2',
            'prefix': v2_match.group(1),
            'ciphertext': v2_match.group(2),
            'username': username
        }

    # 查找V1版本密码
    v1_match = password_v1_pattern.search(content)
    if v1_match:
        return {
            'version': 'V1',
            'ciphertext': v1_match.group(1),
            'username': username
        }

    # 如果有用户名但没密码
    if username:
        return {
            'version': None,
            'ciphertext': None,
            'username': username
        }

    return None

def decrypt_password(password_info, config_passphrase):
    """
    使用解密算法解密密码
    """
    try:
        if password_info['version'] == 'V2':
            # V2/V3 逻辑
            crypto = SecureCRTCryptoV2(config_passphrase)
            return crypto.decrypt(password_info['ciphertext'], prefix=password_info['prefix'])
        elif password_info['version'] == 'V1':
            # V1 逻辑
            crypto = SecureCRTCrypto()
            return crypto.decrypt(password_info['ciphertext'])
    except Exception as e:
        return f"解密失败: {str(e)}"
    return ""

# ======================== 主函数逻辑 ========================
def main():
    # 1. 获取配置密码
    print("="*50)
    print("SecureCRT 批量密码提取工具")
    print("="*50)
    print("请输入CRT配置主密码 (Passphrase)\n* 若无主密码请直接回车\n* 若解密出乱码，请确认此密码是否正确:")
    config_passphrase = input("> ").strip()
    
    # 2. 自动定位 Sessions 目录
    # 假设 Sessions 文件夹在脚本同级目录下
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sessions_dir = os.path.join(current_dir, 'Sessions')
    
    if not os.path.isdir(sessions_dir):
        print(f"\n错误: 未找到目录 '{sessions_dir}'")
        print("请将该脚本放在与 'Sessions' 文件夹相同的目录下。")
        return

    print(f"\n[1] 正在扫描目录: {sessions_dir}")

    # 3. 初始化并写入记录
    record_count = 0
    fail_count = 0

    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(CSV_HEADERS)

            for root, dirs, files in os.walk(sessions_dir):
                for file in files:
                    if file.endswith('.ini'):
                        file_path = os.path.join(root, file)
                        
                        # 计算层级
                        relative_path = os.path.relpath(root, sessions_dir)
                        dir_level = 'root' if relative_path == '.' else relative_path.replace(os.sep, '-')

                        # 提取
                        info = extract_password_info(file_path)
                        
                        if info:
                            decrypted = ""
                            if info['ciphertext']:
                                decrypted = decrypt_password(info, config_passphrase)
                            
                            writer.writerow([
                                dir_level,
                                file,
                                info['username'],
                                decrypted,
                                info['version'] or "None"
                            ])
                            record_count += 1
                        else:
                            # 仅记录完全无法解析的文件
                            fail_count += 1

        print("\n" + "="*50)
        print(f"处理完成！")
        print(f"成功记录: {record_count} 条")
        if fail_count > 0:
            print(f"无法解析文件: {fail_count} 个 (可能是非会话配置文件)")
        print(f"结果已保存到: {os.path.abspath(OUTPUT_CSV)}")
        print("="*50)

    except PermissionError:
        print(f"\n错误: 无法写入 {OUTPUT_CSV}。请确保该文件没有被 Excel 等程序打开。")

if __name__ == '__main__':
    main()
