import tkinter.font as tkFont
from tkinter import ttk
from tkinter import *
from tkinter import messagebox
import tkinter as tk
from tkinter import filedialog
import hmac
import hashlib
import os
import Crypto.Cipher.ARC4 as RC4
import struct
import sys

class ecc_uti():
    BLOCK_TYPE_SMALL = 0x0
    BLOCK_TYPE_BIG_ON_SMALL = 0x1
    BLOCK_TYPE_BIG = 0x02

    def calcecc(self,data):
        assert len(data) == 0x210
        val = 0
        for i in range(0x1066):
            if not i & 31:
                v = ~struct.unpack("<L", data[i // 8:i // 8 + 4])[0]
            val ^= v & 1
            v >>= 1
            if val & 1:
                val ^= 0x6954559
            val >>= 1
        val = ~val
        return data[:-4] + struct.pack("<L", (val << 6) & 0xFFFFFFFF)

    def addecc(self,data, block=0, off_8=b"\x00" * 4, block_type=BLOCK_TYPE_BIG_ON_SMALL):
        res = b""
        while len(data):
            d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
            data = data[0x200:]

            if block_type == self.BLOCK_TYPE_BIG_ON_SMALL:
                d += struct.pack("<BL3B4s4s", 0, block // 32, 0xFF, 0, 0, off_8, b"\0\0\0\0")
            elif block_type == self.BLOCK_TYPE_BIG:
                d += struct.pack("<BL3B4s4s", 0xFF, block // 256, 0, 0, 0, off_8, b"\0\0\0\0")
            elif block_type == self.BLOCK_TYPE_SMALL:
                d += struct.pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\0\0\0\0")
            else:
                raise ValueError("Block type not supported")
            d = self.calcecc(d)
            block += 1
            res += d
        return res

    def unecc(self,image):
        res = b""
        for s in range(0, len(image), 528):
            res += image[s:s + 512]
        return res

    def unecc_fast(self,image):
        return b''.join([image[s:s + 512] for s in range(0, len(image), 528)])

    def verify(self,data, block=0, off_8=b"\x00" * 4):
        while len(data):
            d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
            d += struct.pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\0\0\0\0")
            d = self.calcecc(d)
            calc_ecc = d[0x200:]
            file_ecc = data[0x200:0x210]
            if calc_ecc != file_ecc:
                print("Ecc mismatch on page 0x{:02X} (0x{:02X})".format(block, (block + 1) * 0x210 - 0x10))
                print(file_ecc)
                print(calc_ecc)
            block += 1
            data = data[0x210:]

    def help(self):
        print("Usage: {} [-u][-e][-v] file".format(sys.argv[0]))

    def main(self):
        if len(sys.argv) < 3:
            self.help()
            return

        with open(sys.argv[2], "rb") as f:
            image = f.read()

        if sys.argv[1] == "-u":
            image = self.unecc(image)
            with open(sys.argv[2] + ".unecc", "wb") as f:
                f.write(image)
        elif sys.argv[1] == "-e":
            image = self.addecc(image)
            with open(sys.argv[2] + ".ecc", "wb") as f:
                f.write(image)
        elif sys.argv[1] == "-v":
            self.verify(image)
        else:
            self.help()
            return

    def __init__(self):
        pass


class from2to3():
    def decrypt_CB(self,CB, key):
        key = hmac.new(key, CB[0x10:0x20], hashlib.sha1).digest()[0:0x10]
        CB = CB[0:0x10] + key + RC4.new(key).decrypt(CB[0x20:])
        return CB

    def decrypt_CB_B(self,cbb, cba, cpukey):
        secret = cba[0x10:0x20]
        h = hmac.new(secret, None, hashlib.sha1)
        h.update(cbb[0x10:0x20])
        h.update(cpukey)
        key = h.digest()[0:0x10]
        CB = cbb[0:0x10] + key + RC4.new(key).decrypt(cbb[0x20:])
        return CB

    def criar(self,argv):
        ecc_utils = ecc_uti()
        print("*RGH2 to 3 by DrSchottky*\n")
        if len(argv) != 3 or not os.path.isfile(argv[0]) or not os.path.isfile(argv[1]):
            return "Usage: RGH3_ECC.bin updflash.bin CPUKEY outfile.bin"

        cpukey = bytearray.fromhex(argv[2])
        if len(cpukey) != 16:
            return "CPU Key com Tamanho errado"

        print("Loading ECC")
        with open(argv[0], "rb") as f:
            ecc = f.read()

        if len(ecc) == 1351680:
            print("ECC contains spare data")
            ecc = ecc_utils.unecc(ecc)
        elif len(ecc) == 1310720:
            print("ECC does not contain spare data")
        else:
            return "Ecc com tamanho errado"

        print("\nExtracting RGH3 SMC")
        (rgh3_smc_len, rgh3_smc_start) = struct.unpack(">LL", ecc[0x78:0x80])
        rgh3_smc = ecc[rgh3_smc_start:rgh3_smc_len + rgh3_smc_start]
        loader_start = struct.unpack("!L", ecc[0x8:0xC])[0]

        print("\nExtracting RGH3 Bootloaders")
        (loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", ecc[
                                                                                                   loader_start:loader_start + 16])
        print("Found {} {} with size 0x{:08X} at 0x{:08X}".format(loader_name.decode(), loader_ver, loader_size,
                                                                  loader_start))
        rgh3_cba = ecc[loader_start:loader_start + loader_size]
        loader_start += loader_size

        (loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", ecc[
                                                                                                   loader_start:loader_start + 16])
        print("Found {} {} with size 0x{:08X} at 0x{:08X}".format(loader_name.decode(), loader_ver, loader_size,
                                                                  loader_start))
        rgh3_payload = ecc[loader_start:loader_start + loader_size]

        if not rgh3_payload or not rgh3_cba:
            return "Missing ECC bootloaders. Aborting"

        print("\nLoading FB")
        with open(argv[1], "rb") as f:
            fb = f.read()
        fb_with_ecc = False

        if len(fb) == 17301504 or len(fb) == 69206016:
            print("FB image contains spare data")
            xell_start = 0x73800
            patchable_fb = fb[:xell_start]
            patchable_fb = ecc_utils.unecc(patchable_fb)
            fb_with_ecc = True
        elif len(fb) == 50331648:
            print("FB image does not contain spare data")
            xell_start = 0x70000
            patchable_fb = fb[:xell_start]
        else:
            return "Backup com tamanho incorreto"

        if fb_with_ecc:
            spare_sample = fb[0x4400:0x4410]

            if spare_sample[0].to_bytes(1, 'big') == b'\xff':
                print("Detected 256/512MB Big Block Flash")
                block_type = ecc_utils.BLOCK_TYPE_BIG
            elif spare_sample[5].to_bytes(1, 'big') == b'\xff':
                if spare_sample[0:2] == b"\x01\x00":
                    print("Detected 16/64MB Small Block Flash")
                    block_type = ecc_utils.BLOCK_TYPE_SMALL
                elif spare_sample[0:2] == b"\x00\x01":
                    print("Detected 16/64MB Big on Small Flash")
                    block_type = ecc_utils.BLOCK_TYPE_BIG_ON_SMALL
                else:
                    return "Can't detect Flash type. Aborting"
            else:
                return "Can't detect Flash type. Aborting"
        else:
            print("Detected 4GB Flash")

        if fb[xell_start:xell_start + 0x10] != b"\x48\x00\x00\x20\x48\x00\x00\xEC\x48\x00\x00\x00\x48\x00\x00\x00":
            return "Xell header not found. Aborting"

        print("\nPatching SMC")
        patchable_fb = patchable_fb[:rgh3_smc_start] + rgh3_smc + patchable_fb[rgh3_smc_start + rgh3_smc_len:]

        print("\nExtracting FB bootloaders")

        loader_start = struct.unpack("!L", patchable_fb[0x8:0xC])[0]

        (loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", patchable_fb[
                                                                                                   loader_start:loader_start + 16])
        print("Found {} {} with size 0x{:08X} at 0x{:08X}".format(loader_name.decode(), loader_ver, loader_size,
                                                                  loader_start))
        fb_cba = patchable_fb[loader_start:loader_start + loader_size]
        fb_cba_start = loader_start
        loader_start += loader_size

        (loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", patchable_fb[
                                                                                                   loader_start:loader_start + 16])
        print("Found {} {} with size 0x{:08X} at 0x{:08X}".format(loader_name.decode(), loader_ver, loader_size,
                                                                  loader_start))
        fb_cbb = patchable_fb[loader_start:loader_start + loader_size]
        fb_cbb_start = loader_start

        print("\nDecrypting CB")
        key_1bl = b"\xDD\x88\xAD\x0C\x9E\xD6\x69\xE7\xB5\x67\x94\xFB\x68\x56\x3E\xFA"
        plain_fb_cba = self.decrypt_CB(fb_cba, key_1bl)
        fb_cbb = self.decrypt_CB_B(fb_cbb, plain_fb_cba, cpukey)
        if fb_cbb[0x392:0x39a] not in [b"\x58\x42\x4F\x58\x5F\x52\x4F\x4D", b"\x00" * 8]:
            return "CB_B decryption error (wrong CPU key?). Aborting"
        # sys.exit(0)

        print("\nPatching CB")
        original_size = len(patchable_fb)
        new_cbb = rgh3_payload + fb_cbb
        patchable_fb = patchable_fb[:fb_cba_start] + rgh3_cba + new_cbb + patchable_fb[fb_cbb_start + len(fb_cbb):]
        new_size = len(patchable_fb)
        print("I had to remove 0x{:02X} bytes after CE to make it fit.".format(new_size - original_size))
        patchable_fb = patchable_fb[:original_size]

        print("\nMerging image")
        if fb_with_ecc:
            patchable_fb = ecc_utils.addecc(patchable_fb, block_type=block_type)
        fb = patchable_fb + fb[len(patchable_fb):]
        return fb


class Gui():
    def question(self,titulo,mensagem):
        MsgBox = tk.messagebox.askquestion(titulo, mensagem,
                                           icon='warning')
        if MsgBox == 'yes':
            return True
        else:
            return False


    def getText(self):
        return self.txtCPUKEY.get('1.0', 'end')

    def fileChooser(self):
        filetypes = (
            ('All files', '*.*'),
        )
        filename = tk.filedialog.askopenfilenames(
            title='Selecione o arquivo...',
            filetypes=filetypes,
        )
        return filename



    def fileSave(self,file):
        filetypes = (
            ('Bin', '*.Bin'),
        )
        filename = filedialog.asksaveasfilename(initialdir="/", title="Save File",
                                                     filetypes=filetypes)

        if(filename.lower().find(".bin")==-1 and filename.lower()!=""):
            filename+=".bin"


        print(filename)
        try:
            with open(filename, "wb") as f:
                 f.write(file)
            return True,filename
        except:
            return False,filename

    def getECC(self):
        ecc=self.fileChooser()
        self.cbECC["values"]=ecc
        if (len(self.cbECC["values"]) > 0):
            self.cbECC.current(0)



    def getBackup(self):
        backup=self.fileChooser()
        self.cbBackup["values"]=backup
        if (len(self.cbBackup["values"]) > 0):
            self.cbBackup.current(0)


    def __init__(self,root):
        root.title("RGH 3.0")
        width=350
        height=200
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        self.lbCPUKEY=ttk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        self.lbCPUKEY["font"] = ft
        self.lbCPUKEY["justify"] = "center"
        self.lbCPUKEY["text"] = "CpuKey"
        self.lbCPUKEY.place(x=30,y=20,width=142,height=20)

        self.txtCPUKEY=Text(root)
        self.txtCPUKEY["borderwidth"] = "1px"
        ft = tkFont.Font(family='Times',size=10)
        self.txtCPUKEY["font"] = ft
        self.txtCPUKEY["fg"] = "#333333"
        self.txtCPUKEY.place(x=80,y=20,width=228,height=20)


        self.lbECC = ttk.Label(root)
        ft = tkFont.Font(family='Times', size=10)
        self.lbECC["font"] = ft
        self.lbECC["justify"] = "center"
        self.lbECC["text"] = "ECC 3.0"
        self.lbECC.place(x=30, y=50, width=50, height=25)

        self.cbECC=ttk.Combobox(root)
        ft = tkFont.Font(family='Times',size=10)
        self.cbECC["font"] = ft
        self.cbECC["justify"] = "center"
        self.cbECC["state"]= "readonly"
        self.cbECC["values"]=[]
        self.cbECC.place(x=80,y=50,width=228,height=25)
        self.cbECC["postcommand"] = self.getECC


        self.lbBackup = ttk.Label(root)
        ft = tkFont.Font(family='Times', size=10)
        self.lbBackup["font"] = ft
        self.lbBackup["justify"] = "center"
        self.lbBackup["text"] = "Backup"
        self.lbBackup.place(x=30, y=80, width=50, height=25)

        self.cbBackup = ttk.Combobox(root)
        ft = tkFont.Font(family='Times', size=10)
        self.cbBackup["font"] = ft
        self.cbBackup["justify"] = "center"
        self.cbBackup["state"] = "readonly"
        self.cbBackup.place(x=80, y=80, width=228, height=25)
        self.cbBackup["postcommand"]=self.getBackup


        self.btnIniciar = ttk.Button(root)
        self.btnIniciar["text"] = "Iniciar"
        self.btnIniciar.place(x=100, y=120, width=70, height=25)
        self.btnIniciar["command"] = self.iniciar

        self.btnSair = ttk.Button(root)
        self.btnSair["text"] = "Sair"
        self.btnSair.place(x=170, y=120, width=70, height=25)
        self.btnSair["command"] =self.sair


    def sair(self):
        sys.exit()

    def iniciar(self):
        cpuKey=self.getText().replace("\n","")
        backup=self.cbBackup["values"][0]
        ecc=self.cbECC["values"][0]
        converter=from2to3()
        arquivo=converter.criar([ecc,backup,cpuKey])
        if(type(arquivo) is type("")):
            messagebox.showerror("Error", arquivo)
        else:
            confirmacao,local=self.fileSave(arquivo)
            if(confirmacao):
                messagebox.showerror("Arquivo Salvo","Arquivo Saldo em: {}".format(local))
            elif(local!=""):
                messagebox.showerror("Error", "Erro ao salvar o arquivo em: {}".format(local))
            else:
                pass


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    root = tk.Tk()
    #root.iconbitmap(os.getcwd() + '/Interface/ico.ico')
    app = Gui(root)
    root.mainloop()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
