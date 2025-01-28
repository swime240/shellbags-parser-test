import sys
import regipy
import datetime
import csv

# UsrClass.datを読み込んでBagMRUの情報を返す
def load_usrclass(path):
    usrclass_bagmru_path = '\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU'
    try:
        usrclass_reg = regipy.RegistryHive(path)
        bagmru = usrclass_reg.get_key(usrclass_bagmru_path)
        return bagmru
    except FileNotFoundError:
        exit('エラー：指定したファイルが存在しません。UsrClass.datを指定してください。')
    except regipy.exceptions.RegistryKeyNotFoundException as e:
        exit(f'エラー：キーが存在しません。\n{e}')
    except Exception as e:
        exit(f'エラー：指定したファイルが正しくない可能性があります。UsrClass.datを指定してください。\n{type(e).__name__}：{e}')

# ドライブ配下のキーを再帰的に解析する
def analyze_bagmru_recursive(key):
    result = {}
    if key.subkey_count > 0:
        for value in key.get_values():
            parsed_dict = parse_folder_data(value)
            if parsed_dict:
                subkey = key.get_subkey(value.name)
                result[subkey.name] = parsed_dict
                result[subkey.name].update({'subkey_count' : subkey.subkey_count})
                result[subkey.name].update(analyze_bagmru_recursive(subkey))
    return result

# データフィールドを解析してフォルダに関する情報を抽出する
def parse_folder_data(value):
    parsed_dict = {}

    # Value Nameが数字の場合
    if value.name.isdecimal():
        data = value.value
        class_type = hex(data[2])
        ver_offset = data[-4]

        # クラスタイプ識別子が0x31（フォルダ）か0x35（フォルダ名にマルチバイトを含む）の場合
        if class_type == '0x31' or class_type == '0x35':
            update_date = convert_fat32time(data[8:12]) # 最終更新日時
            create_date = convert_fat32time(data[ver_offset+8:ver_offset+12]) # 作成日時
            last_access_date = convert_fat32time(data[ver_offset+12:ver_offset+16]) # 最終アクセス日時
            
            # フォルダ名を取得
            folder_name = data[ver_offset+46:-6]
            folder_end = folder_name.find(b'\x00\x00')
            if folder_end > 0:
                folder_name = folder_name[:folder_end+1]
            
            parsed_dict['name'] = folder_name.decode('utf-16', errors='ignore')
            parsed_dict['update_date'] = update_date
            parsed_dict['create_date'] = create_date
            parsed_dict['last_access_date'] = last_access_date
    return parsed_dict

# FAT32形式のタイムスタンプをdatetimeに変換
def convert_fat32time(fat32time):
    try:
        date_bytes = fat32time[:2]
        time_bytes = fat32time[2:]
        date = int.from_bytes(date_bytes, byteorder='little')
        time = int.from_bytes(time_bytes, byteorder='little')
        year = (date >> 9) + 1980
        month = (date >> 5) & 0b1111
        day = date & 0b11111
        hour = time >> 11
        minute = (time >> 5) & 0b111111
        second = (time & 0b11111) * 2
        converted_time = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
        return converted_time.astimezone(datetime.timezone(datetime.timedelta(hours=9)))
    except ValueError:
        return ''
    
# 多次元辞書からCSVに出力する用のリストを構築する
def dict_to_list_recursive(directory, prefix_key='', prefix_path=''):
    result_list = []
    for key, value in directory.items():
        new_list = []
        current_key = prefix_key + key
        current_path = prefix_path
        if isinstance(value, dict):
            if 'name' in value:
                current_path = current_path + value['name']
                new_list = [current_key, current_path, value['subkey_count'], value['create_date'], value['update_date'], value['last_access_date']]
                result_list.append(new_list)
            result_list.extend(dict_to_list_recursive(value, current_key + '\\', current_path + '\\'))
    return result_list

# メイン
def main():

    # 出力するファイル
    output_csv = 'analyzed_ShellBags.csv'

    # UsrClass.datの読み込み
    args = sys.argv
    if len(args) < 2:
        exit('引数にUsrClass.datを指定してください。')
    bagmru = load_usrclass(args[1])

    # ルートフォルダシェルアイテムからThis PCを探索
    this_pc_key = ''
    for bagmru_val in bagmru.get_values():
        # Value Nameが数字の場合
        if bagmru_val.name.isdecimal():
            bagmru_data = bagmru_val.value

            # This PCかチェック（一応GUIDまで確認）
            if bagmru_data[3:4].hex() == '50':
                guid = bagmru_data[4:20]
                guid_0 = int.from_bytes(guid[0:4], 'little')
                guid_1 = int.from_bytes(guid[4:6], 'little')
                guid_2 = int.from_bytes(guid[6:8], 'little')
                guid_3 = int.from_bytes(guid[8:10], 'big')
                guid_4 = int.from_bytes(guid[10:], 'big')
                converted_guid = f'{{{guid_0:x}-{guid_1:x}-{guid_2:x}-{guid_3:x}-{guid_4:x}}}'
                if converted_guid == '{20d04fe0-3aea-1069-a2d8-8002b30309d}':
                    print(f'This PCのキー： {bagmru_val.name}')
                    this_pc_key = bagmru_val.name
                    break
    
    if not this_pc_key:
        exit('This PCが見つかりません…。')

    # This PCの情報をshellbags_dictにセット
    this_pc = bagmru.get_subkey(this_pc_key)
    this_pc_key_path = 'BagMRU\\' + this_pc_key
    this_pc_info = {'name':'Desktop\\This PC', 'update_date':'', 'create_date':'', 'last_access_date':'', 'subkey_count':this_pc.subkey_count}
    shellbags_dict = {this_pc_key:this_pc_info}
    
    # ドライブまでの情報を取得
    print('\nドライブ情報（キー：ドライブレター）')
    for pc_val in this_pc.get_values():
        if pc_val.name.isdecimal():
            pc_data = pc_val.value

            # ドライブの場合はクラスタイプ識別子が0x2f
            if pc_data[2:3].hex() == '2f':
                drive_key = this_pc.get_subkey(pc_val.name)
                drive_name = pc_data[3:5].decode('utf-8')
                drive_info = {'name':drive_name, 'update_date':'', 'create_date':'', 'last_access_date':'', 'subkey_count':drive_key.subkey_count}
                shellbags_dict[this_pc_key][pc_val.name] = drive_info
                print(f'{pc_val.name}： {drive_name}')

                # ドライブ配下のキーを再帰的に解析し、shellbags_dictを更新
                analyzed_dict = analyze_bagmru_recursive(drive_key)
                shellbags_dict[this_pc_key][pc_val.name].update(analyzed_dict)

    # 解析結果の多次元辞書をリストに変換し、CSVとして出力する
    result_list = dict_to_list_recursive(shellbags_dict)
    label_list = ['キー', 'パス', 'サブキー数', '作成日時', '更新日時', '最終アクセス日時']
    result_list.insert(0, label_list)
    with open(output_csv, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(result_list)
    
    print(f'\n解析完了： ' + output_csv)


if __name__ == '__main__':
    main()