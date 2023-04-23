import crypt
import sys
import os
import random
import string
from datetime import datetime
import pyzipper

# 获取Python脚本文件的绝对路径
script_path = os.path.abspath(sys.argv[0])
Info = {'Version': 0.1,
        'Name': 'compress',
        'Function':'''使用公钥加密文件或者使用私钥解密文件''',
        'Help':'compress encrypt <folder> \ncompress decrypt <zip file> \ncompress <folder> \ncompress <zip file>',}

def compress_encrypt_folders(src_folders, output_file, password=None, comment=''):
    with pyzipper.AESZipFile(output_file, 'w', encryption=pyzipper.WZ_AES) as archive:
        if password is not None:
            archive.setpassword(password.encode())
        archive.comment = comment.encode()
        for src_folder in src_folders:
            for folder_name, subfolders, filenames in os.walk(src_folder):
                for filename in filenames:
                    file_path = os.path.join(folder_name, filename)
                    archive.write(file_path, os.path.relpath(file_path, os.path.dirname(src_folder)))

def compress_encrypt_file(src_file, output_file, password=None, comment=''):
    with pyzipper.AESZipFile(output_file, 'w', encryption=pyzipper.WZ_AES) as archive:
        if password is not None:
            archive.setpassword(password.encode())
        archive.comment = comment.encode()
        archive.write(src_file)


def read_comment_zip(archive_file):
    with pyzipper.AESZipFile(archive_file, 'r') as archive:
        comment = archive.comment.decode()
        # print("Comment:", comment)
    return comment


def decompress_folder(src_file, dest_folder, password):
    with pyzipper.AESZipFile(src_file, 'r') as archive:
        archive.setpassword(password.encode())
        archive.extractall(dest_folder)

def decompress_file(src_file, dest_folder = '', password = None):
    # print(f"dest_folder = {dest_folder}")
    with pyzipper.AESZipFile(src_file, 'r') as archive:
        if password:
            archive.setpassword(password.encode())
        archive.extractall(dest_folder)

def read_filenames_zip(archive_file, password = None):
    with pyzipper.ZipFile(archive_file, 'r') as archive:
        if password:
            archive.setpassword(password.encode())
        filenames = [info.filename for info in archive.infolist()]
    # print(f'In file {archive_file} filenames = {filenames}')
    return filenames

def generate_password(keylen=13):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=keylen))


def get_zip_name(ziptype='zip'):
    date_str = datetime.now().strftime("%Y%m%d")
    # time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    zip_name = f"{date_str}.{ziptype}"
    i = 1
    while os.path.exists(zip_name):
        zip_name = f"{date_str}-{i}.{ziptype}"
        i += 1
    return zip_name

def encrypt_folders(folders):
    zip_outer_name = get_zip_name()
    zip_inner_name = f'{datetime.now().strftime("%Y%m%d%H%M%S")}.zip'
    password = generate_password()
    encrypted_password = crypt.router([sys.argv[0], 'encrypt', password])
    if isinstance(encrypted_password, bytes):
        encrypted_password = encrypted_password.decode()
    if not isinstance(folders, list):
        folders = [folders, ]
    compress_encrypt_folders(folders, zip_inner_name, password)
    compress_encrypt_file(zip_inner_name, zip_outer_name, password='whosyourdaddy', comment=encrypted_password)
    os.remove(zip_inner_name)

def decrypt_file(zip_outer_name):
    encrypted_password = read_comment_zip(zip_outer_name)
    password = crypt.router([sys.argv[0], 'decrypt', 'private_key.pem', encrypted_password])
    if isinstance(password, bytes):
        password = password.decode()
    # print(password)
    zip_inner_name = read_filenames_zip(zip_outer_name, password=None)[0]
    # print(f'zip_inner_name = {zip_inner_name}')
    decompress_file(zip_outer_name, dest_folder = '', password = 'whosyourdaddy')
    FileNamesInInnerZIP = read_filenames_zip(zip_inner_name, password=password)
    zip_inner_folders = list()
    for name in FileNamesInInnerZIP:
        if '/' in name:
            zip_inner_folders.append(name.split('/')[0])
    # print(zip_inner_folders)
    if len(set(zip_inner_folders)) == 1:
        des_folder = ''
        print(f'Inner ZIP file has only one folder, unzip to unique folder: {zip_inner_folders[0]}')
    else:
        des_folder = os.path.splitext(os.path.basename(zip_outer_name))[0]
        print(f'Inner ZIP file has no folder, unzip folder as zip_outer_name: {des_folder}')
    decompress_file(zip_inner_name, dest_folder=des_folder, password=password)
    os.remove(zip_inner_name)
    return None

def router(argv):
    if len(argv) == 2 and argv[1] in ['-h', '--help']:
        print(Info.get('Help'))
        return
    elif len(argv) == 2 and argv[1] in ['-V', '--version']:
        print(Info.get('Version'))
        return
    elif len(argv) == 2 and os.path.isdir(argv[1]) and not argv[1].lower().endswith(".zip"):
        encrypt_folders(argv[1])
        return
    elif len(argv) == 2 and os.path.isfile(argv[1]) and not argv[1].lower().endswith(".zip"):
        print(f'Current not support zip file')
        return
    elif len(argv) == 2 and os.path.isfile(argv[1]) and argv[1].lower().endswith(".zip"):
        decrypt_file(argv[1])
        return
    if len(argv) < 3:
        print("Usage: python encrypt_decrypt.py encrypt/decrypt <folder/file(s) or rar_file>")
        return

    operation = argv[1].lower()

    if operation not in ["encrypt", "decrypt"]:
        print("Invalid operation, please use 'encrypt' or 'decrypt'")
        return

    first_arg = argv[2]

    if operation == "encrypt":
        if os.path.isdir(first_arg) and len(argv) == 3:
            # files = [os.path.join(first_arg, f) for f in os.listdir(first_arg)]
            folder = first_arg
            encrypt_folders(folder)
        else:
            print("Invalid input, please provide a folder for decryption.")

    elif operation == "decrypt":
        # print(first_arg)
        # print(os.path.abspath(first_arg))
        # print(f'os.path.isfile("{first_arg}") = {os.path.isfile(os.path.abspath(first_arg))}')
        # print(f'{first_arg}.lower().endswith(".rar") = {first_arg.lower().endswith(".rar")}')
        if os.path.isfile(first_arg) and first_arg.lower().endswith(".zip"):
            decrypt_file(first_arg)
        else:
            print("Invalid input, please provide a rar file for decryption.")

    else:
        print("Invalid input, please provide a folder or file(s) for encryption, or a rar file for decryption.")


def main():
    router(sys.argv)
    input("Press Enter to continue...")

if __name__ == "__main__":
    main()
