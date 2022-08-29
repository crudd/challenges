# Secret Design Document

I. Based on concept of WSL (Windows Subsystem for Linux) samples Black Lotus Labs found in the wild

    a. Initial samples did not work in our test environment
    b. Research led to a full WSL to Windows shellcode injection chain

II. GoLang is used to call Powershell (transitioning context to Windows, allowing usage of Windows APIs)
	
III.	Powershell executes a Python script that Base64 decodes shellcode and uses Python ctypes to allocate memory, inject, and then execute the shellcode

IV.	The shellcode uses the Windows APIs to read the clipboard (imitating stealing clipboard or other credentials using other APIs/methods)

V.	The clipboard contents is checked against a hardcoded value, and if correct, it decrypts and displays the flag; otherwise it displays an 'Error' messagebox
