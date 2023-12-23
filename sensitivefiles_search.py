import os
import re
import threading
from queue import Queue
from tqdm import tqdm

# 指定需要搜索的文件类型
INCLUDED_EXTENSIONS = {'.php', '.inc', '.txt', '.word', '.asp', '.jsp', '.jspx'}

def search_files_for_keywords(file_queue, keywords, pbar, output_file):
    while True:
        file_path = file_queue.get()
        if file_path is None:
            break

        # 使用 tqdm.write 来避免干扰进度条
        tqdm.write(f"正在搜索: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()

            for i, line in enumerate(lines):
                if any(re.search(keyword, line, re.IGNORECASE | re.UNICODE) for keyword in keywords):
                    start = max(0, i - 3)
                    end = min(i + 4, len(lines))
                    context = ''.join(lines[start:end])
                    with open(output_file, 'a', encoding='utf-8') as out:
                        out.write(f"\n文件: {file_path}\n{context}")
                    break
        except Exception as e:
            tqdm.write(f"Error reading file {file_path}: {e}")

        file_queue.task_done()
        pbar.update(1)

def main():
    disk_path = input("请输入要搜索的磁盘路径（例如：C:\\）: ")
    if not os.path.exists(disk_path):
        print("指定的磁盘路径不存在。")
        return

    sensitive_keywords = ["passwords", "用户名", "账户口令", "username", "pass", "user", "password", "密码", "口令"]
    output_file = "sensitive_info_results.txt"

    file_queue = Queue()
    total_files = 0

    for root, _, files in os.walk(disk_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in INCLUDED_EXTENSIONS:
                file_path = os.path.join(root, file)
                file_queue.put(file_path)
                total_files += 1

    pbar = tqdm(total=total_files, desc="搜索进度", position=0)

    num_threads = 10
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=search_files_for_keywords, args=(file_queue, sensitive_keywords, pbar, output_file))
        thread.start()
        threads.append(thread)

    for _ in range(num_threads):
        file_queue.put(None)
    for thread in threads:
        thread.join()

    pbar.close()

    print(f"\n搜索完成。共搜索了 {total_files} 个文件。结果已保存在 '{output_file}'。")

if __name__ == "__main__":
    main()
