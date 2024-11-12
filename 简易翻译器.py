import json
import re

import requests
import time
import hashlib
import base64
from Crypto.Cipher import AES
import tkinter as tk


def replace_punctuation_to_english(text):
    chinese_punctuations = "，。！？；："
    english_punctuations = ",.!?;:"
    translation_table = str.maketrans(chinese_punctuations, english_punctuations)
    return text.translate(translation_table)


def get_md5(val, is_hex=True):
    md5 = hashlib.md5()
    md5.update(val.encode())
    if is_hex:
        return md5.hexdigest()
    else:
        return md5.digest()


def translate():
    result_str = []
    s = input_text.get("1.0", tk.END).strip()
    s_text = replace_punctuation_to_english(s)
    values = re.split(r"(?<=[^A - Za - z0 - 9])[。.?!](?=[^A - Za - z0 - 9])", s_text)
    for value in values:
        url = "https://dict.youdao.com/webtranslate"

        mysticTime = str(int(time.time() * 1000))
        # print(mysticTime)

        d = 'fanyideskweb'
        e = mysticTime
        u = 'webfanyi'
        t = 'fsdsogkndfokasodnaso'
        s = f"client={d}&mysticTime={e}&product={u}&key={t}"
        # print("s:::", s)
        sign = get_md5(s)
        data = {
            'i': value,
            'from': 'auto',
            'to': '',
            'useTerm': 'false',
            'dictResult': 'true',
            'keyid': 'webfanyi',
            'sign': sign,
            'client': 'fanyideskweb',
            'product': 'webfanyi',
            'appVersion': '1.0.0',
            'vendor': 'web',
            'pointParam': 'client,mysticTime,product',
            'mysticTime': mysticTime,
            'keyfrom': 'fanyi.web',
            'mid': 1,
            'screen': 1,
            'model': 1,
            'network': 'wifi',
            'abtest': 0,
            'yduuid': 'abcdefg',
        }
        my_headers = {
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "connection": "keep-alive",
            "content-length": "310",
            "content-type": "application/x-www-form-urlencoded",
            "cookie": "OUTFOX_SEARCH_USER_ID=-1579052434@60.1.78.51; OUTFOX_SEARCH_USER_ID_NCOO=1920932921.1181278; DICT_DOCTRANS_SESSION_ID=OGQyOGRlYTgtNTVjMC00OTQ5LTHjMGEtM2VkZTI2MmJlM2Qw",
            "host": "dict.youdao.com",
            "origin": "https://fanyi.youdao.com",
            "referer": "https://fanyi.youdao.com/",
            "sec-ch-ua": "\"Chromium\";v=\"130\", \"Microsoft Edge\";v=\"130\", \"Not?A_Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
        }
        res = requests.post(url, data=data, headers=my_headers)
        res_encrypt_base64 = res.text.replace("-", "+").replace("_", "/")
        # print("res_encrypt_base64:::", res_encrypt_base64)

        res_encrypt = base64.b64decode(res_encrypt_base64)
        # print("res_encrypt:::", res_encrypt)

        o = 'ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl'

        n = 'ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4'
        key = get_md5(o, is_hex=False)
        iv = get_md5(n, is_hex=False)
        aes = AES.new(key, AES.MODE_CBC, iv)
        source_data = aes.decrypt(res_encrypt).decode()
        if source_data is None:
            print("source_data 为 None，无法进行清理操作，请检查数据来源。")
            # 或者可以设置一个默认值，假设这里设置为空字符串
            source_data_str = ""
        else:
            source_data_str = source_data.rstrip(source_data[-1])

        # print(source_data_str)
        source_data_json = json.loads(source_data_str)
        result = source_data_json['translateResult'][0][0]['tgt']
        result_str.append(result)
    result_str = "".join(result_str)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result_str)


if __name__ == '__main__':
    root = tk.Tk()
    root.title("简易翻译器")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = 470
    window_height = 287
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    root.geometry(f"470x287+{x}+{y}")

    input_text = tk.Text(root, height=5, width=50)
    input_text.pack(pady=10)

    translate_button = tk.Button(root, text="翻译", command=translate)
    translate_button.pack(pady=5)

    output_text = tk.Text(root, height=5, width=50)
    output_text.pack(pady=10)

    root.mainloop()
